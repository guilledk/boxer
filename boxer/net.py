#!/usr/bin/env python3

import trio
import json
import socket
import logging

from functools import partial

from nacl.public import PublicKey, PrivateKey, Box

from triopatterns import AsyncQueue

from boxer.rpc import rpc_response_mod


logger = logging.getLogger(__name__)


PACKET_LENGTH = 16 * 1024  # 16kb


class UDPContext:
    """
    A UDP Context represents a  conection with a remote udp endpoint at "addr",
    can  performing a  background key exchange using  "key" as its  private key
    it grants  an simple interface for  encrypted comunications through  socket
    "sock".
    """

    F_KEYEX = 0

    def __init__(
        self,
        addr,
        key,
        sock
            ):

        self.addr = addr
        self.key = key
        self.sock = sock

        self.inbound = AsyncQueue()

    async def send_raw(self, data, encrypted=True):

        logger.debug(f"outbound to {self.addr}: {data}")

        if hasattr(self, "box") and encrypted:
            data = self.box.encrypt(data)

        await self.sock.sendto(
            data,
            self.addr
            )

    async def send_str(self, string, encrypted=True):
        await self.send_raw(
            string.encode("utf-8"),
            encrypted=encrypted
            )

    async def send_json(self, obj, encrypted=True):
        await self.send_str(
            json.dumps(obj),
            encrypted=encrypted
            )

    # rpc assumes obj as "id" field and creates a subscriber queue to match the
    # response  message that  should contain the  same unique  "id" field, then
    # returns response.
    async def rpc(self, method, params, id, encrypted=True):
        async with self.inbound.modify(
            rpc_response_mod,
            args=[id],
            history=False
                ) as resp_queue:

            await self.send_json(
                {
                    "jsonrpc": "2.0",
                    "method": method,
                    "params": params,
                    "id": id
                    },
                encrypted=encrypted
                )

            msg = await resp_queue.receive()

            return msg

    async def _bg_key_exchange(self, nursery):

        # send key right away and await remote key
        nursery.start_soon(
            partial(
                self.send_raw,
                bytes(self.key.public_key),
                encrypted=False
                )
            )

        async with self.inbound.subscribe(
            lambda *args: isinstance(args[0], bytes) and (len(args[0]) == 32),
            history=True
                ) as pkqueue:
            data = await pkqueue.receive()

        self.remote_pkey = PublicKey(data)
        self.box = Box(self.key, self.remote_pkey)

        await self.inbound.send(UDPContext.F_KEYEX)

    # runs background key exchange
    def start_bgkeyex(self, nursery):
        nursery.start_soon(
            self._bg_key_exchange,
            nursery
            )

    # await until background key exchange is finished
    async def wait_keyex(self):
        async with self.inbound.subscribe(
            lambda *args: args[0] == UDPContext.F_KEYEX,
            history=True
                ) as queue:
            await queue.receive()

    # for inbound self-generation, drops all data not from self.addr
    async def inbound_generator(self):
        with trio.CancelScope() as self.inbound_cscope:
            while True:

                data, addr = await self.sock.recvfrom(PACKET_LENGTH)

                if self.addr != addr:
                    continue

                if hasattr(self, "box"):
                    data = self.box.decrypt(data)

                logger.debug(f"inbound from {addr}: {data}")

                await self.inbound.send(data)

    def start_inbound(self, nursery):
        nursery.start_soon(
            self.inbound_generator
            )

    def stop_inbound(self):
        if hasattr(self, "inbound_cscope"):
            self.inbound_cscope.cancel()

    # for debug
    def __repr__(self):
        if hasattr(self, "remote_pkey"):
            return f"[{bytes(self.remote_pkey).hex()[:8]} @ {self.addr}]"
        else:
            return f"[!NO KEY! @ {self.addr}]"


class UDPGate:

    """
    For each  address that sends a user datagram to this socket a UDPContext is
    created  and it's key exchange is started, saves  contexts in a  dictionary
    indexed by recipient address.
    """

    def __init__(
        self,
        nursery,
        key=None
            ):

        self.nursery = nursery

        self.contexts = {}
        self.conn_cb = None
        self.sock = trio.socket.socket(
            socket.AF_INET,
            socket.SOCK_DGRAM
            )

        self.key = PrivateKey.generate() if key is None else key

    async def bind(
        self,
        addr,
        conn_cb=None  # new connection callback
            ):
        await self.sock.bind(addr)

        logger.debug(f"bind to {addr}")

        self.conn_cb = conn_cb
        self.nursery.start_soon(
            self.inbound_generator
            )

    async def inbound_generator(self):
        with trio.CancelScope() as self.inbound_cscope:

            while True:

                data, addr = await self.sock.recvfrom(PACKET_LENGTH)

                if addr not in self.contexts:
                    udpctx = UDPContext(
                        addr,
                        self.key,
                        self.sock
                        )
                    udpctx.start_bgkeyex(
                        self.nursery
                        )
                    self.contexts[addr] = udpctx
                    self.nursery.start_soon(
                        self.conn_cb,
                        udpctx
                        )
                else:
                    udpctx = self.contexts[addr]
                    if hasattr(udpctx, "box"):
                        data = udpctx.box.decrypt(data)

                logger.debug(f"inbound from {addr}: {data}")

                await udpctx.inbound.send(data)

    def close(self):
        if hasattr(self, "inbound_cscope"):
            self.inbound_cscope.cancel()

        self.sock.close()
