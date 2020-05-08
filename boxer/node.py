#!/usr/bin/env python3

import os
import trio
import math
import socket
import logging

from datetime import datetime

from nacl.public import PrivateKey, PublicKey, Box

from triopatterns import AsyncQueue, SessionIDManager

from boxer.core import BoxerServer, BoxerFight

from boxer.net import UDPContext

from boxer.rpc import (
    ServerResponseError,
    NodeResponseError,
    JSONRPCResponseResult,
    JSONRPCResponseError,
    rpc_request_mod
    )


logger = logging.getLogger(__name__)


class PunchTimeoutError(Exception):
    pass


class NodeNotFoundError(Exception):
    pass


class DontHitYourselfError(Exception):
    pass


class BoxerNode:

    def __init__(
        self,
        server_addr,
        nursery,
        key=None,
        evade_fights=False
            ):

        self.nursery = nursery
        self.evade_fights = evade_fights

        if key is None:
            self.key = PrivateKey.generate()
        else:
            self.key = PrivateKey(bytes.fromhex(key))

        self.node_directory = {}
        self.pcktidmngr = SessionIDManager()
        self.server_ctx = UDPContext(
            server_addr,
            self.key,
            trio.socket.socket(
                socket.AF_INET,
                socket.SOCK_DGRAM
                )
            )

        self.fights = AsyncQueue()
        self.events = AsyncQueue()

    async def introduction(
        self,
        name,
        desc="",
        secret=True
            ):

        self.name = name
        self.desc = desc
        self.secret = secret

        self.server_ctx.start_inbound(self.nursery)
        self.server_ctx.start_bgkeyex(self.nursery)
        await self.server_ctx.wait_keyex()

        # introduce ourselves
        params = {
            "name": self.name
        }
        if self.desc != "":
            params["desc"] = self.desc

        if self.secret:
            params["secret"] = {}

        resp = await self.server_ctx.rpc(
            "introduction",
            params,
            self.pcktidmngr.getid()
            )

        if resp["result"] != "ok":
            raise ServerResponseError(f"server didn't return \'ok\': {resp}")

        # begin listening server rpcs
        self.nursery.start_soon(
            self.rpc_request_consumer
            )

    async def rpc_request_consumer(self):

        methods = {}
        methods["event"] = self.remote_event
        methods["fight"] = self.remote_fight

        with trio.CancelScope() as self.rpc_cscope:
            async with self.server_ctx.inbound.modify(
                rpc_request_mod
                    ) as rpc_queue:
                while True:
                    cmd = await rpc_queue.receive()

                    method = cmd["method"]
                    if method in methods:
                        self.nursery.start_soon(
                            methods[method],
                            cmd["params"],
                            cmd["id"]
                            )

                    else:
                        await self.server_ctx.send_json(
                            JSONRPCResponseError(
                                "0",
                                "protocol error",
                                cmd["id"]
                                ).as_json()
                            )

    async def remote_event(self, params, id):
        etype = params["type"]
        key = params["pkey"]

        if etype == "introduction":
            self.node_directory[key] = {
                "name": params["name"]
            }
            if "desc" in params:
                self.node_directory[key]["desc"] = params["desc"]

        elif etype == "goodbye":
            del self.node_directory[key]

        await self.events.send(params)

    async def remote_fight(self, params, pid):
        if self.evade_fights:
            result = "evade"
        else:
            result = "take"
            self.nursery.start_soon(
                self._bg_fight,
                params["with"],
                params["fid"]
                )

        await self.server_ctx.send_json(
            JSONRPCResponseResult(
                result,
                pid
                ).as_json()
            )

    async def _bg_fight(
        self,
        nkey,
        fid
            ):

        # create new udp context with server

        fight_ctx = UDPContext(
            self.server_ctx.addr,
            self.key,
            trio.socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            )
        fight_ctx.start_inbound(self.nursery)
        fight_ctx.start_bgkeyex(self.nursery)
        await fight_ctx.wait_keyex()

        resp = await fight_ctx.rpc(
            "punch",
            {
                "fid": fid
                },
            self.pcktidmngr.getid(),
            timeout=10
            )

        if "result" not in resp:
            raise ServerResponseError(f"server returned error: {resp}")

        result = resp["result"]

        # change udp context encryption to use peer pkey
        fight_ctx.remote_pkey = PublicKey(bytes.fromhex(nkey))

        # also point to peer external endpoint
        fight_ctx.set_addr(
            (result["host"], result["port"]),
            Box(
                fight_ctx.key,
                fight_ctx.remote_pkey
                )
            )

        punch_total_len = 1024 * 8
        punch_packet = b"punch"
        punch_garbage_len = punch_total_len - 1 - len(punch_packet)
        punched_trough = False

        fight_ended = False

        def digits(n):
            if n > 0:
                return int(math.log10(n)) + 1
            elif n == 0:
                return 1
            else:
                # n must be > 0
                raise AssertionError

        while not fight_ended:

            async with fight_ctx.inbound.subscribe(
                    lambda *args: isinstance(args[0], bytes) and
                    (punch_packet in args[0]),
                    history=True
                        ) as punch_queue:

                attack_scope = trio.CancelScope()

                async def attack():
                    # hopefully both clients syncronize to send their packets
                    # try to sleep until next second
                    # now x 10^(-1 * digits(now))
                    tstamp = datetime.now().microsecond
                    await trio.sleep(1 - (tstamp * math.pow(10, -digits(tstamp))))

                    with attack_scope:
                        with trio.move_on_after(1):
                            while True:
                                await fight_ctx.send_raw(
                                    punch_packet +
                                    b'=' +
                                    os.urandom(punch_garbage_len)
                                    )

                self.nursery.start_soon(attack)

                with trio.move_on_after(2.6):
                    msg = await punch_queue.receive()
                    logger.debug("got punched!")
                    punched_trough = True
                    attack_scope.cancel()

            resp = await fight_ctx.rpc(
                "round",
                {
                    "fid": fid,
                    "result":
                        BoxerFight.STATUS_KO if punched_trough
                        else BoxerFight.STATUS_TIMEOUT
                    },
                self.pcktidmngr.getid(),
                dest=self.server_ctx.addr
                )

            if resp["result"] == "done":
                fight_ended = True

                fight_ctx.addr_whitelist.remove(self.server_ctx.addr)
                del fight_ctx.boxes[self.server_ctx.addr]

                await self.fights.send((fid, fight_ctx))
                logger.warning("boxer punch through.")

            elif resp["result"] == "fail":
                fight_ended = True
                await self.fights.send((fid, None))
                logger.warning("boxer punch failure.")
            else:
                logger.warning("boxer punch error. retrying...")

    async def fight(self, pkey, scope=None):
        if scope is None:
            scope = trio.CancelScope()

        with scope:
            while True:
                resp = await self.server_ctx.rpc(
                    "fight",
                    {
                        "target": pkey
                        },
                    self.pcktidmngr.getid()
                    )

                if "result" in resp:
                    if resp["result"] == "evade":
                        return None

                    fid = resp["result"]

                    async with self.fights.subscribe(
                        lambda *args: args[0][0] == args[1],
                        args=[fid],
                        history=False
                            ) as fight_queue:

                        self.nursery.start_soon(
                            self._bg_fight,
                            pkey,
                            fid
                            )

                        fid, fight_ctx = await fight_queue.receive()

                        if fight_ctx is not None:
                            return fight_ctx

                elif resp["error"]["code"] == "1":
                    raise NodeNotFoundError

                elif resp["error"]["code"] == "2":
                    raise DontHitYourselfError

    async def goodbye(self):

        with trio.move_on_after(4):
            resp = await self.server_ctx.rpc(
                "goodbye", {}, self.pcktidmngr.getid()
                )

        if hasattr(self, "rpc_cscope"):
            self.rpc_cscope.cancel()

        self.server_ctx.stop_inbound()
