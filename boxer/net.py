#!/usr/bin/env python3

# until python 4.0 i must import this
# https://www.python.org/dev/peps/pep-0563/
from __future__ import annotations

import trio
import json
import socket
import logging

from typing import Callable, Optional, Tuple, Dict

from functools import partial

from nacl.public import PublicKey, PrivateKey, Box

from triopatterns import AsyncQueue

from boxer.rpc import rpc_response_mod


logger = logging.getLogger(__name__)


PACKET_LENGTH = 32 * 1024  # 16kb

IPv4Address = Tuple[str, int]


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
        addr: IPv4Address,
        key: PrivateKey,
        sock: trio.socket.socket
            ):
        self.key = key
        self.sock = sock

        self.inbound = AsyncQueue()

        self.addr_whitelist: List[IPv4Address] = []
        self.boxes: Dict[IPv4Address, Box] = {}

        self.set_addr(addr, None)

    def set_addr(
        self,
        new_addr: IPv4Address,
        new_box: Optional[Box]
            ) -> None:

        self.addr = new_addr
        self.boxes[new_addr] = new_box
        self.addr_whitelist.append(new_addr)

        return None

    async def send_raw(
        self,
        data: bytes,
        encrypted: bool = True,
        dest: Optional[IPv4Address] = None
            ) -> None:

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

        if b"punch=" not in raw_data:
            logger.debug(f"sent to {dest}: {raw_data}")

        return None

    async def send_str(
        self,
        string: str,
        encrypted: bool = True,
        dest: Optional[IPv4Address] = None
            ) -> None:

        await self.send_raw(
            string.encode("utf-8"),
            encrypted=encrypted,
            dest=dest
            )

        return None

    async def send_json(
        self,
        obj: str,
        encrypted: bool = True,
        dest: Optional[IPv4Address] = None
            ) -> None:

        await self.send_str(
            json.dumps(obj),
            encrypted=encrypted,
            dest=dest
            )

        return None

    # rpc assumes obj as "id" field and creates a subscriber queue to match the
    # response  message that  should contain the  same unique  "id" field, then
    # returns response.
    async def rpc(
        self,
        method: str,
        params: Dict,
        pid: str,
        encrypted: bool = True,
        timeout: int = 5,
        max_attempts: int = 3,
        dest: Optional[IPv4Address] = None
            ) -> Dict:

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
        nursery: trio.Nursery,
        whitelist: Optional[PublicKey] = None
            ) -> None:

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

        return None

    # runs background key exchange
    def start_bgkeyex(
        self,
        nursery: trio.Nursery,
        whitelist: Optional[PublicKey] = None
            ) -> None:

        nursery.start_soon(
            partial(
                self._bg_key_exchange,
                nursery,
                whitelist=whitelist
                )
            )

        return None

    # await until background key exchange is finished
    async def wait_keyex(self) -> None:
        async with self.inbound.subscribe(
            lambda *args:
                (args[0] == UDPContext.F_KEYEX) or
                (args[0] == UDPContext.F_DROPPED),
            history=True
                ) as queue:
            res = await queue.receive()

            if res == UDPContext.F_DROPPED:
                raise NotInWhitelistError

        return None

    # for inbound self-generation, drops all data not from self.addr
    async def inbound_generator(self) -> None:
        logger.debug(f"starting inbound from {self.addr}")
        with trio.CancelScope() as self.inbound_cscope:
            while True:

                data, addr = await self.sock.recvfrom(PACKET_LENGTH)

                if addr not in self.addr_whitelist:
                    logger.debug(f"dropping packet {data} from {addr}. not in whitelist")
                    continue

                if self.boxes[addr] is not None:
                    data = self.boxes[addr].decrypt(data)

                if b"punch=" not in data:
                    logger.debug(f"inbound from {addr}: {data}")

                await self.inbound.send(data)

        return None

    def start_inbound(self, nursery) -> None:
        nursery.start_soon(
            self.inbound_generator
            )

        return None

    def stop_inbound(self) -> None:
        if hasattr(self, "inbound_cscope"):
            self.inbound_cscope.cancel()

        return None

    # for debug
    def __repr__(self) -> str:
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
        nursery: trio.Nursery,
        key: PrivateKey = None,
        whitelist: Optional[PublicKey] = None
            ):

        self.nursery = nursery

        self.contexts: Dict[IPv4Address, UDPContext] = {}
        self.conn_cb: Optional[Callable[[UDPContext], None]] = None
        self.sock = trio.socket.socket(
            socket.AF_INET,
            socket.SOCK_DGRAM
            )

        self.key = PrivateKey.generate() if key is None else key
        self.whitelist = whitelist

    async def bind(
        self,
        addr: IPv4Address,
        conn_cb: Optional[Callable[[UDPContext], None]] = None
            ) -> None:

        await self.sock.bind(addr)

        logger.debug(f"bind to {addr}")

        self.conn_cb = conn_cb
        self.nursery.start_soon(
            self.inbound_generator
            )

        return None

    async def inbound_generator(self) -> None:
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

                if b"punch=" not in data:
                    logger.debug(f"inbound from {addr}: {data}")

                await udpctx.inbound.send(data)

        return None

    def close(self) -> None:
        if hasattr(self, "inbound_cscope"):
            self.inbound_cscope.cancel()

        self.sock.close()

        return None
