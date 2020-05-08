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


PACKET_LENGTH = 32 * 1024  # 16kb


class NotInWhitelistError(Exception):
    pass


class RPCTimeoutError(Exception):
    pass


class UDPContext:
    """
    A UDP Context represents a  conection with a remote udp endpoint at "addr",
    can  performing a  background key exchange using  "key" as its  private key
    it grants  an simple interface for  encrypted comunications through  socket
    "sock".
    """

    F_KEYEX = 0
    F_DROPPED = 1

    def __init__(
        self,
        addr,
        key,
        sock
            ):
        self.key = key
        self.sock = sock

        self.inbound = AsyncQueue()

        self.addr_whitelist = []
        self.boxes = {}

        self.set_addr(addr, None)

    def set_addr(self, new_addr, new_box):
        self.addr = new_addr
        self.boxes[new_addr] = new_box
        self.addr_whitelist.append(new_addr)

    async def send_raw(self, data, encrypted=True, dest=None):

        if dest is None:
            dest = self.addr

        raw_data = data
        if encrypted and \
            dest in self.boxes and \
                self.boxes[dest] is not None:

            data = self.boxes[dest].encrypt(data)

        await self.sock.sendto(
            data,
            dest
            )

        logger.debug(f"sent to {dest}: {raw_data}")

    async def send_str(self, string, encrypted=True, dest=None):
        await self.send_raw(
            string.encode("utf-8"),
            encrypted=encrypted,
            dest=dest
            )

    async def send_json(self, obj, encrypted=True, dest=None):
        await self.send_str(
            json.dumps(obj),
            encrypted=encrypted,
            dest=dest
            )

    # rpc assumes obj as "id" field and creates a subscriber queue to match the
    # response  message that  should contain the  same unique  "id" field, then
    # returns response.
    async def rpc(
        self,
        method,
        params,
        pid,
        encrypted=True,
        timeout=5,
        max_attempts=3,
        dest=None
            ):

        async with self.inbound.modify(
            rpc_response_mod,
            args=[pid]
                ) as resp_queue:

            msg = None
            attempt = 1
            while (msg is None) and (attempt <= max_attempts):
                with trio.move_on_after(timeout):
                    await self.send_json(
                        {
                            "jsonrpc": "2.0",
                            "method": method,
                            "params": params,
                            "id": pid
                            },
                        encrypted=encrypted,
                        dest=dest
                        )

                    msg = await resp_queue.receive()

                if msg is None:
                    logger.warning(
                        f"rpc timeout {pid}, attempt number {attempt}."
                        )

                attempt += 1

            if msg is None:
                raise RPCTimeoutError

            return msg

    async def _bg_key_exchange(
        self,
        nursery,
        whitelist=None
            ):

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

        rkey = PublicKey(data)

        # drop context if not in whitelist
        if (whitelist is not None) and \
                (rkey not in whitelist):
            await self.inbound.send(UDPContext.F_DROPPED)
            return

        self.remote_pkey = rkey
        self.boxes[self.addr] = Box(self.key, self.remote_pkey)

        await self.inbound.send(UDPContext.F_KEYEX)

    # runs background key exchange
    def start_bgkeyex(
        self,
        nursery,
        whitelist=None
            ):

        nursery.start_soon(
            partial(
                self._bg_key_exchange,
                nursery,
                whitelist=whitelist
                )
            )

    # await until background key exchange is finished
    async def wait_keyex(self):
        async with self.inbound.subscribe(
            lambda *args:
                (args[0] == UDPContext.F_KEYEX) or
                (args[0] == UDPContext.F_DROPPED),
            history=True
                ) as queue:
            res = await queue.receive()

            if res == UDPContext.F_DROPPED:
                raise NotInWhitelistError

    # for inbound self-generation, drops all data not from self.addr
    async def inbound_generator(self):
        logger.debug(f"starting inbound from {self.addr}")
        with trio.CancelScope() as self.inbound_cscope:
            while True:

                data, addr = await self.sock.recvfrom(PACKET_LENGTH)

                if addr not in self.addr_whitelist:
                    logger.debug(f"dropping packet {data} from {addr}. not in whitelist")
                    continue

                if self.boxes[addr] is not None:
                    data = self.boxes[addr].decrypt(data)

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
        key=None,
        whitelist=None
            ):

        self.nursery = nursery

        self.contexts = {}
        self.conn_cb = None
        self.sock = trio.socket.socket(
            socket.AF_INET,
            socket.SOCK_DGRAM
            )

        self.key = PrivateKey.generate() if key is None else key
        self.whitelist = whitelist

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
                        self.nursery,
                        whitelist=self.whitelist
                        )
                    self.contexts[addr] = udpctx
                    self.nursery.start_soon(
                        self.conn_cb,
                        udpctx
                        )
                else:
                    udpctx = self.contexts[addr]
                    if udpctx.boxes[addr] is not None:
                        data = udpctx.boxes[addr].decrypt(data)

                logger.debug(f"inbound from {addr}: {data}")

                await udpctx.inbound.send(data)

    def close(self):
        if hasattr(self, "inbound_cscope"):
            self.inbound_cscope.cancel()

        self.sock.close()
