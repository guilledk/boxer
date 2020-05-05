#!/usr/bin/env python3

import trio
import logging
import argparse

from nacl.public import PublicKey, PrivateKey, Box

from triopatterns import AsyncQueue, SessionIDManager

from boxer.net import UDPGate

from boxer.rpc import (
    JSONRPCRequest,
    JSONRPCResponseResult,
    JSONRPCResponseError,
    rpc_request_mod
    )


class BoxerRemoteNode:

    def __init__(
        self,
        ctx,
        server
            ):

        self.main_ctx = ctx
        self.key = ctx.remote_pkey
        self.server = server

        self.box = Box(self.server.key, self.key)
        self.event_queue = AsyncQueue()
        self.pcktidmngr = SessionIDManager()
        self.rpc_cscopes = []

    # event outbound queue
    async def event_consumer(self):
        with trio.CancelScope() as self.event_cscope:
            while True:
                event = await self.event_queue.receive()
                await self.main_ctx.send_json(
                    JSONRPCRequest(
                        "event",
                        event,
                        self.pcktidmngr.getid()
                        ).as_json()
                    )

    # rpc inbound queue
    async def rpc_request_consumer(self, ctx):

        methods = {}

        methods["introduction"] = self.boxer_introduction
        methods["fight"] = self.boxer_fight
        methods["punch"] = self.boxer_punch
        methods["goodbye"] = self.boxer_goodbye

        local_cancel_scope = trio.CancelScope()
        self.rpc_cscopes.append(local_cancel_scope)

        with trio.CancelScope() as local_cancel_scope:
            async with ctx.inbound.modify(
                rpc_request_mod
                    ) as rpc_queue:
                while True:
                    cmd = await rpc_queue.receive()

                    method = cmd["method"]
                    if method in methods:
                        self.server.nursery.start_soon(
                            methods[method],
                            cmd["params"],
                            ctx,
                            cmd["id"]
                            )

                    else:
                        await ctx.send_json(
                            JSONRPCResponseError(
                                "0",
                                "protocol error",
                                cmd["id"]
                                ).as_json()
                            )

    async def stop(self):

        if hasattr(self, "event_cscope"):
            self.event_cscope.cancel()

        for lcscope in self.rpc_cscopes:
            lcscope.cancel()

    def __repr__(self):
        return repr(self.main_ctx)

    # boxer protocol method implementations

    async def boxer_introduction(self, params, ctx, id):

        # validate params & load node info
        if "name" not in params:
            await ctx.send_json(
                JSONRPCResponseError(
                    "0",
                    "protocol error",
                    id
                    ).as_json()
                )
            return

        self.name = params["name"]

        if "desc" in params:
            self.desc = params["desc"]

        self.secret = "secret" in params

        # respond
        await ctx.send_json(
            JSONRPCResponseResult(
                "ok",
                id
                ).as_json()
            )

        # if not secret broadcast node introduction event
        if not self.secret:
            event_params = {
                "type": "introduction",
                "pkey": bytes(self.key).hex(),
                "name": self.name
                }
            if hasattr(self, "desc"):
                event_params["desc"] = self.desc

            await self.server.broadcast(
                event_params,
                self
                )

        # send node directory as introduction events
        nodes = [
            item for item in self.server.nodes.items()
            if item[0] != self.key
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

            await self.event_queue.send(event_params)

        # finally begin sending events to new node
        self.server.nursery.start_soon(
            self.event_consumer
            )

    async def boxer_goodbye(self, params, ctx, id):

        if not self.secret:
            await self.server.broadcast(
                {
                    "type": "goodbye",
                    "pkey": bytes(self.key).hex()
                    },
                self
                )

        del self.server.nodes[self.key]

        await ctx.send_json(
            JSONRPCResponseResult(
                "goodbye",
                id
                ).as_json()
            )

        await self.stop()

    async def boxer_fight(self, params, ctx, id):

        # validate params
        if "target" not in params:
            await ctx.send_json(
                JSONRPCResponseError(
                    "0",
                    "protocol error",
                    id
                    ).as_json()
                )
            return

        tkey = PublicKey(bytes.fromhex(params["target"]))

        if tkey not in self.server.nodes:
            await ctx.send_json(
                JSONRPCResponseError(
                    "1",
                    "node not found",
                    id
                    ).as_json()
                )

        else:

            target_node = self.server.nodes[tkey]

            fid = self.server.fightidmngr.getid()
            self.server.fights[fid] = {
                "ctxs": []
                }

            # send fight req to target node
            resp = await target_node.main_ctx.rpc(
                "fight",
                {
                    "with": bytes(self.key).hex(),
                    "fid": fid
                    },
                target_node.pcktidmngr.getid()
                )

            result = resp["result"]
            if result == "take":
                result = fid
            else:
                del self.server.fights[fid]

            await ctx.send_json(
                JSONRPCResponseResult(
                    result,
                    id
                    ).as_json()
                )

    async def boxer_punch(self, params, ctx, id):

        if "fid" not in params:
            await ctx.send_json(
                JSONRPCResponseError(
                    "0",
                    "protocol error",
                    id
                    ).as_json()
                )
            return

        # add context to fight dict
        fid = params["fid"]
        fight = self.server.fights[fid]
        fight["ctxs"].append((ctx, id))

        # if this node is  the last one to  punch, begin udp  external endpoint
        # exchange
        if len(fight["ctxs"]) == 2:
            node0_ctx, node0_pid = fight["ctxs"][0]
            node0 = self.server.nodes[node0_ctx.remote_pkey]
            node1_ctx, node1_pid = fight["ctxs"][1]
            node1 = self.server.nodes[node1_ctx.remote_pkey]

            self.server.nursery.start_soon(
                node0_ctx.send_json,
                JSONRPCResponseResult(
                    {
                        "host": node1_ctx.addr[0],
                        "port": node1_ctx.addr[1]
                        },
                    node0_pid
                    ).as_json()
                )

            self.server.nursery.start_soon(
                node1_ctx.send_json,
                JSONRPCResponseResult(
                    {
                        "host": node0_ctx.addr[0],
                        "port": node0_ctx.addr[1]
                        },
                    node1_pid
                    ).as_json()
                )


class BoxerServer:

    BOX_VERSION = "0.1.0"
    BOX_MAX_PACKET_LENGTH = 4096

    def __init__(
        self,
        nursery,
        host="0.0.0.0",
        port=12000,
        key=None
            ):

        self.nursery = nursery
        self.host = host
        self.port = port

        if key is None:
            self.key = PrivateKey.generate()
        else:
            self.key = PrivateKey(bytes.fromhex(key))

        self.gate = UDPGate(
            nursery,
            key=self.key
            )

        self.nodes = {}
        self.fights = {}
        self.fightidmngr = SessionIDManager()

    async def init(
        self,
        log_path="boxer.log"
            ):

        self.log_file = await trio.open_file(log_path, "w")

        await self.gate.bind(
            (self.host, self.port),
            self.new_connection
            )

    async def stop(self):
        for node in self.nodes.values():
            await node.stop()

        if hasattr(self, "log_file"):
            await self.log_file.aclose()

    async def new_connection(self, ctx):

        await ctx.wait_keyex()

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

    async def broadcast(self, event, origin_node):

        target_nodes = [
            node for node in self.nodes.values()
            if node is not origin_node
            ]

        for node in target_nodes:
            await node.event_queue.send(event)


async def start_server():

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-k", "--key", type=str,
        help=f"set private key"
        )

    args = parser.parse_args()

    async with trio.open_nursery() as nursery:

        server = BoxerServer(
            nursery,
            key=args.key if args.key else None
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
