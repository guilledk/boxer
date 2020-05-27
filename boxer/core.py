#!/usr/bin/env python3

# until python 4.0 i must import this
# https://www.python.org/dev/peps/pep-0563/
from __future__ import annotations

import trio
import logging
import argparse

from typing import Dict, Union

from nacl.public import PublicKey, PrivateKey, Box

from triopatterns import AsyncQueue, SessionIDManager

from boxer.net import IPv4Address, UDPGate, NotInWhitelistError

from boxer.rpc import (
    JSONRPCRequest,
    JSONRPCResponseResult,
    JSONRPCResponseError,
    rpc_request_mod
    )

logger = logging.getLogger(__name__)


class BoxerFight:

    STATUS_FIGHT = "fight"
    STATUS_KO = "ko"
    STATUS_TIMEOUT = "timeout"

    def __init__(
        self,
        fid: str
            ):

        self.fid = fid
        self.round = 1

        self.nodes: Dict[UDPContext, BoxerRemoteNode] = {}
        self.status: Dict[UDPContext, str] = {}
        self.ctxts: List[UDPContext] = []
        self.pids: Dict[UDPContext, Dict[str, Union[str, int]]] = {}

    def addctx(
        self,
        node: BoxerRemoteNode,
        ctx: UDPContext,
        punch_id: str
            ) -> None:

        self.nodes[ctx] = node
        self.status[ctx] = BoxerFight.STATUS_FIGHT

        self.ctxts.append(ctx)

        self.pids[ctx] = {
            "punch_id": punch_id,
            "round_id": -1
        }

        return None


class BoxerRemoteNode:

    def __init__(
        self,
        ctx: UDPContext,
        server: BoxerServer
            ):

        self.main_ctx = ctx
        self.key = ctx.remote_pkey
        self.server = server

        self.box = Box(self.server.key, self.key)
        self.event_queue = AsyncQueue()
        self.pcktidmngr = SessionIDManager()

        self.pid_history: Dict[str, Dict] = {}
        self.rpc_cscopes: Dict[UDPContext, trio.CancelScope] = {}

    # event outbound queue
    async def event_consumer(self) -> None:
        with trio.CancelScope() as self.event_cscope:
            while True:
                event = await self.event_queue.receive()
                await self.main_ctx.send_json(
                    JSONRPCRequest(
                        "event",
                        event,
                        str(uuid.uuid4())
                        ).as_json()
                    )

        return None

    # rpc inbound queue
    async def rpc_request_consumer(self, ctx: UDPContext) -> None:

        local_cancel_scope = trio.CancelScope()
        self.rpc_cscopes[ctx] = local_cancel_scope

        logger.debug(f"started rpc consumer for {ctx}")

        with trio.CancelScope() as local_cancel_scope:
            async with ctx.inbound.modify(
                rpc_request_mod
                    ) as rpc_queue:
                while True:
                    cmd = await rpc_queue.receive()

                    if cmd["id"] not in self.pid_history:

                        self.server.nursery.start_soon(
                            self.server.eval,
                            self,
                            ctx,
                            cmd
                            )

                    else:
                        logger.warning(
                            f"repeated packet \"{cmd['id']}\" at {self}."
                            )

                        self.server.nursery.start_soon(
                            ctx.send_json,
                            self.pid_history[cmd["id"]]
                            )

        return None

    async def stop(self) -> None:

        if hasattr(self, "event_cscope"):
            self.event_cscope.cancel()

        for lcscope in self.rpc_cscopes.values():
            lcscope.cancel()

        return None

    def __repr__(self) -> str:
        return repr(self.main_ctx)


class BoxerServer:

    BOX_VERSION = "0.1.0"
    BOX_MAX_PACKET_LENGTH = 4096

    def __init__(
        self,
        nursery: trio.Nursery,
        addr: IPv4Address = ("0.0.0.0", 12000),
        key: PrivateKey = None,
        max_rounds: int = 2
            ):

        self.nursery = nursery
        self.addr = addr
        self.max_rounds = max_rounds

        if key is None:
            self.key = PrivateKey.generate()
        else:
            self.key = PrivateKey(bytes.fromhex(key))

        self.nodes: Dict[PublicKey, BoxerRemoteNode] = {}
        self.fights: Dict[str, BoxerFight] = {}
        self.fightidmngr = SessionIDManager()

    async def init(self) -> None:

        whitelist = None
        if await trio.Path("whitelist").exists():
            async with await trio.open_file("whitelist", "r") as wlistf:
                whitelist = [
                    PublicKey(bytes.fromhex(line.rstrip()))
                    for line in await wlistf.readlines()
                    ]

            logger.debug(f"loaded whitelist of size {len(whitelist)}.")

        if await trio.Path("key").exists():
            async with await trio.open_file("key", "r") as keyf:
                self.key = PrivateKey(
                    bytes.fromhex((await keyf.read()).rstrip())
                    )

            logger.debug(f"loaded key from file.")

        self.gate = UDPGate(
            self.nursery,
            key=self.key,
            whitelist=whitelist
            )

        await self.gate.bind(
            self.addr,
            self.new_connection
            )

        return None

    async def stop(self) -> None:
        for node in self.nodes.values():
            await node.stop()

        return None

    async def new_connection(self, ctx: UDPContext) -> None:

        try:
            await ctx.wait_keyex()

        except NotInWhitelistError:
            logger.warning(f"dropped {ctx.addr}. reason: not in whitelist.")
            return

        if ctx.remote_pkey not in self.nodes:
            self.nodes[ctx.remote_pkey] = BoxerRemoteNode(
                ctx,
                self
                )

        # begin listening to rpcs in this ctx
        self.nursery.start_soon(
            self.nodes[ctx.remote_pkey].rpc_request_consumer,
            ctx
            )

        return None

    async def broadcast(
        self,
        event: Dict,
        origin_node: BoxerRemoteNode
            ) -> None:

        target_nodes = [
            node for node in self.nodes.values()
            if node is not origin_node
            ]

        for node in target_nodes:
            await node.event_queue.send(event)

        return None

    """
    BOXER PROTOCOL IMPLEMENTATIONS
    """

    async def boxer_introduction(
        self,
        params: Dict,
        node: BoxerRemoteNode,
        ctx: UDPContext,
        pid: str
            ) -> Dict:

        # validate params & load node info
        if "name" not in params:
            return JSONRPCResponseError(
                "0",
                "protocol error",
                pid
                ).as_json()

        node.name = params["name"]
        node.main_ctx = ctx

        if "desc" in params:
            node.desc = params["desc"]

        node.secret = "secret" in params

        # if not secret broadcast node introduction event
        if not node.secret:
            event_params = {
                "type": "introduction",
                "pkey": bytes(node.key).hex(),
                "name": node.name
                }
            if hasattr(node, "desc"):
                event_params["desc"] = node.desc

            await self.broadcast(
                event_params,
                node
                )

        # send node directory as introduction events
        nodes = [
            item for item in self.nodes.items()
            if item[0] != node.key
        ]
        for nkey, node in nodes:

            # check if node has been introduced
            # TODO: if this happens the server should send the intro later
            if not hasattr(node, "name"):
                continue

            event_params = {
                "type": "introduction",
                "pkey": bytes(nkey).hex(),
                "name": node.name
                }
            if hasattr(node, "desc"):
                event_params["desc"] = node.desc

            await node.event_queue.send(event_params)

        # finally begin sending events to new node
        self.nursery.start_soon(
            node.event_consumer
            )

        return JSONRPCResponseResult(
            "ok",
            pid
            ).as_json()

    async def boxer_goodbye(
        self,
        params: Dict,
        node: BoxerRemoteNode,
        ctx: UDPContext,
        pid: str
            ) -> Dict:

        if not node.secret:
            await self.broadcast(
                {
                    "type": "goodbye",
                    "pkey": bytes(node.key).hex()
                    },
                node
                )

        del self.nodes[node.key]

        await node.stop()

        return JSONRPCResponseResult(
            "goodbye",
            pid
            ).as_json()

    async def boxer_fight(
        self,
        params: Dict,
        node: BoxerRemoteNode,
        ctx: UDPContext,
        pid: str
            ) -> Dict:

        # validate params
        if "target" not in params:
            return JSONRPCResponseError(
                "0",
                "protocol error",
                pid
                ).as_json()

        tkey = PublicKey(bytes.fromhex(params["target"]))

        if tkey not in self.nodes:
            return JSONRPCResponseError(
                "1",
                "node not found",
                pid
                ).as_json()

        elif tkey == ctx.remote_pkey:
            return JSONRPCResponseError(
                "2",
                "dont hit yourself",
                pid
                ).as_json()

        else:

            target_node = self.nodes[tkey]

            fight = BoxerFight(self.fightidmngr.getid())

            self.fights[fight.fid] = fight

            # send fight req to target node
            resp = await target_node.main_ctx.rpc(
                "fight",
                {
                    "with": bytes(node.key).hex(),
                    "fid": fight.fid
                    },
                target_node.pcktidmngr.getid()
                )

            result = resp["result"]
            if result == "take":
                result = fight.fid
            else:
                del self.fights[fight.fid]

            return JSONRPCResponseResult(
                result,
                pid
                ).as_json()

    async def boxer_punch(
        self,
        params: Dict,
        node: BoxerRemoteNode,
        ctx: UDPContext,
        pid: str
            ) -> Dict:

        if "fid" not in params:
            return JSONRPCResponseError(
                "0",
                "protocol error",
                pid
                ).as_json()

        # add context to fight dict
        fid = params["fid"]
        fight = self.fights[fid]
        fight.addctx(node, ctx, pid)

        # if this node is  the last one to  punch, begin udp  external endpoint
        # exchange
        if len(fight.ctxts) == 2:
            other_ctx = [c for c in fight.ctxts if c != ctx][0]
            other_node = fight.nodes[other_ctx]

            node_pid = fight.pids[ctx]["punch_id"]
            onode_pid = fight.pids[other_ctx]["punch_id"]

            node.pid_history[node_pid] = \
                JSONRPCResponseResult(
                    {
                        "host": other_ctx.addr[0],
                        "port": other_ctx.addr[1]
                        },
                    node_pid
                    ).as_json()

            other_node.pid_history[onode_pid] = \
                JSONRPCResponseResult(
                    {
                        "host": ctx.addr[0],
                        "port": ctx.addr[1]
                        },
                    onode_pid
                    ).as_json()

            self.nursery.start_soon(
                ctx.send_json,
                node.pid_history[node_pid]
                )

            self.nursery.start_soon(
                other_ctx.send_json,
                other_node.pid_history[onode_pid]
                )

        return None

    async def boxer_round(
        self,
        params: Dict,
        node: BoxerRemoteNode,
        ctx: UDPContext,
        pid: str
            ) -> Dict:

        if "fid" not in params or \
                "result" not in params:
            return JSONRPCResponseError(
                "0",
                "protocol error",
                pid
                ).as_json()

        fid = params["fid"]
        result = params["result"]

        fight = self.fights[fid]

        fight.pids[ctx]["round_id"] = pid
        fight.status[ctx] = result

        # if round is finished
        if BoxerFight.STATUS_FIGHT not in fight.status.values():

            ret = ""

            done = True
            for val in fight.status.values():
                done &= val == BoxerFight.STATUS_KO

            if done:
                ret = "done"
                del self.fights[fight.fid]

            elif fight.round > self.max_rounds:
                ret = "fail"
                del self.fights[fight.fid]

            else:
                ret = "retry"
                for c in fight.status:
                    fight.status[c] = BoxerFight.STATUS_FIGHT

                fight.round += 1

            i = 0
            for node_ctx in fight.ctxts:

                _node = fight.nodes[node_ctx]

                # if fight ended discard both contexts
                if ret != "retry":
                    logger.debug(f"stop {node_ctx}")
                    _node.rpc_cscopes[node_ctx].cancel()

                round_pid = fight.pids[node_ctx]["round_id"]

                _node.pid_history[round_pid] = \
                    JSONRPCResponseResult(
                        ret,
                        round_pid
                        ).as_json()

                self.nursery.start_soon(
                    node_ctx.send_json,
                    _node.pid_history[round_pid]
                    )
                i += 1

        return None

    """
    RPC EVALUTATION
    """

    async def eval(
        self,
        node: BoxerRemoteNode,
        ctx: UDPContext,
        cmd: Dict
            ):

        methods = {}

        methods["introduction"] = self.boxer_introduction
        methods["fight"] = self.boxer_fight
        methods["punch"] = self.boxer_punch
        methods["round"] = self.boxer_round
        methods["goodbye"] = self.boxer_goodbye

        method = cmd["method"]
        if method in methods:
            res = await methods[method](
                cmd["params"],
                node,
                ctx,
                cmd["id"]
                )

        else:
            res = JSONRPCResponseError(
                "0",
                "protocol error",
                cmd["id"]
                ).as_json()

        node.pid_history[cmd["id"]] = res

        logger.debug(f"res is: {res}")

        if res is not None:
            await ctx.send_json(
                res
                )


async def start_server():

    logging.basicConfig(
        filename="boxer.log",
        filemode="w",
        format="%(levelname)s - %(asctime)s - %(name)s - %(message)s",
        datefmt="%H:%M:%S",
        level=logging.DEBUG
        )

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-k", "--key", type=str,
        help=f"set private key"
        )
    parser.add_argument(
        "-r", "--rounds", type=int,
        help=f"set max rounds"
        )

    args = parser.parse_args()

    async with trio.open_nursery() as nursery:

        server = BoxerServer(
            nursery,
            key=args.key if args.key else None,
            max_rounds=args.rounds if args.rounds else 2
            )

        await server.init()

        try:
            await trio.sleep_forever()
        finally:
            await server.stop()

if __name__ == '__main__':
    try:
        trio.run(start_server)
    except KeyboardInterrupt:
        pass
