#!/usr/bin/env python3

import trio
import socket

from nacl.public import PrivateKey, PublicKey, Box

from triopatterns import AsyncQueue, SessionIDManager

from boxer.core import BoxerServer

from boxer.net import UDPContext

from boxer.rpc import (
    ServerResponseError,
    NodeResponseError,
    JSONRPCResponseResult,
    JSONRPCResponseError,
    rpc_request_mod
    )


class BoxerNode:

    def __init__(
        self,
        server_addr,
        nursery,
        evade_fights=False
            ):

        self.nursery = nursery
        self.evade_fights = evade_fights

        self.node_directory = {}
        self.key = PrivateKey.generate()
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

    async def remote_fight(self, params, id):
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
                id
                ).as_json()
            )

    async def _bg_fight(self, nkey, fid):

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
            self.pcktidmngr.getid()
            )

        if "result" not in resp:
            raise ServerResponseError(f"server returned error: {resp}")

        result = resp["result"]

        # change udp context encryption to use peer pkey
        fight_ctx.remote_pkey = PublicKey(bytes.fromhex(nkey))
        fight_ctx.box = Box(
            fight_ctx.key,
            fight_ctx.remote_pkey
            )
        # also point to peer external endpoint
        fight_ctx.addr = (
            result["host"],
            result["port"]
            )

        # send two punch packets, 3 is the minimun for it to work
        for x in range(3):
            await fight_ctx.send_raw(b"punch")

        # with a timeout of 5 seconds, await the two remote punches
        with trio.move_on_after(5):
            punched_trough = False

            async with fight_ctx.inbound.subscribe(
                lambda *args: args[0] == b"punch"
                    ) as punch_queue:
                await punch_queue.receive()
                punched_trough = True

        if punched_trough:
            await self.fights.send((fid, fight_ctx))

    async def fight(self, pkey):
        resp = await self.server_ctx.rpc(
            "fight",
            {
                "target": pkey
                },
            self.pcktidmngr.getid()
            )

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

            return fight_ctx

    async def goodbye(self):

        resp = await self.server_ctx.rpc(
            "goodbye", {}, self.pcktidmngr.getid()
            )

        if resp["result"] != "goodbye":
            raise ServerResponseError(f"server returned error: {resp}")

        if hasattr(self, "rpc_cscope"):
            self.rpc_cscope.cancel()

        self.server_ctx.stop_inbound()
