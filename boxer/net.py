#!/usr/bin/env python3

import trio
import json

from nacl.public import PublicKey, PrivateKey, Box

from triopatterns import AsyncQueue


PACKET_LENGTH = 1024


class UDPContext:
    """
    A UDP Context represents a  conection with a remote udp endpoint at "addr",
    can  performing a  background key exchange using  "key" as its  private key
    it grants  an simple interface for  encrypted comunications through  socket
    "sock".
    """

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
        if hasattr(self, box) and encrypted:
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

    async def _bg_key_exchange(self):

        # first msg should be ed25519 raw public key
        data = await self.inbound.receive()

        self.remote_pkey = PublicKey(data)
        self.box = Box(self.key, self.remote_pkey)

        # send our key
        await self.send_raw(
            bytes(self.key.public_key),
            encrypted=False
            )

    def start_bgkeyex(self, nursery):
        nursery.start_soon(
            self._bg_key_exchange
            )


class UDPGate:

    """
    For each  address that sends a user datagram to this socket a UDPContext is
    created  and it's key exchange is started, saves  contexts in a  dictionary
    indexed by recipient address.
    """

    def __init__(
        self,
        nursery
            ):

        self.nursery = nursery

        self.contexts = {}
        self.key = PrivateKey.generate()
        self.sock = trio.socket.socket(
            socket.AF_INET,
            socket.SOCK_DGRAM
            )

    async def bind(
        self,
        addr=("0.0.0.0", 12000)
            ):
        await self.sock.bind(addr)
        self.nursery.start_soon(
            self.inbound_generator
            )

    async def inbound_generator(self):
        with trio.CancelScope() as self.inbound_cscope:

            while True:

                data, addr = await self.sock.recvfrom(PACKET_LENGTH)

                if addr not in self.in:
                    udpctx = UDPContext(
                        addr,
                        self.key,
                        self.sock
                        )
                    udpctx.start_bgkeyex(self.nursery)
                    self.contexts[addr] = udpctx

                await self.contexts[addr].inbound.send(data)

    def close(self):
        if hasattr(self, "inbound_cscope"):
            self.inbound_cscope.cancel()

        self.sock.close()
