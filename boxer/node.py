#!/usr/bin/env python3

import json
import trio
import socket

from boxer.core import BoxerServer, id_matcher

from nacl.public import PrivateKey, PublicKey, Box

from aplutils import AsyncQueue, SessionIDManager


def wildcard_matcher(*args):
    return True


# matches method field from a json obj to be args[1]
def method_matcher(*args):
    tpl = args[0]
    mth = args[1]
    adr = args[2]
    try:
        assert len(tpl) == 2
        assert adr == tpl[1]
        obj = tpl[0]
        assert isinstance(obj, dict)
        assert obj is not None
        assert "method" in obj
        assert mth == obj["method"]
        return True
    except AssertionError:
        return False


def addr_matcher(*args):
    obj = args[0]
    adr = args[1]
    try:
        assert obj is not None
        assert len(obj) == 2
        assert obj[1] == adr
        return True
    except AssertionError:
        return False


def optional_decrypt_id_matcher(*args):
    tpl = args[0]
    uid = args[1]
    box = args[2]
    adr = args[3]
    try:
        assert len(tpl) == 2
        assert adr == tpl[1]
        obj = tpl[0]
        if (box is not False) and (box is not None):
            obj = json.loads(
                box.decrypt(obj).decode("utf-8")
                )

        assert isinstance(obj, dict)
        assert obj is not None
        assert "id" in obj
        assert str(uid) == obj["id"]
        return True
    except AssertionError:
        return False


class BoxerNode:

    def __init__(
        self,
        name,
        nursery,
        desc="",
        secret=False,
        evade_fights=False,
        boxer_host="3.133.35.46",
        boxer_port=12000
            ):

        self.name = name
        self.desc = desc
        self.secret = secret
        self.boxer_host = boxer_host
        self.boxer_port = boxer_port
        self.boxer_addr = (boxer_host, boxer_port)
        self.nursery = nursery
        self.evade_fights = evade_fights

        self.key = PrivateKey.generate()
        self.pcktidmngr = SessionIDManager()

        self.asock = trio.socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.inbound = AsyncQueue()

        self.connections = AsyncQueue()

        self.node_directory = {}

    async def send_json(self, obj, csock=None, caddr=None, cbox=None):

        if (cbox is not False) and ((cbox is not None) or hasattr(self, "box")):
            if cbox is None:
                box = self.box
            else:
                box = cbox
            data = box.encrypt(
                json.dumps(obj)
                    .encode("utf-8")
                )
        else:
            data = json.dumps(obj).encode("utf-8")

        if csock is None:
            sock = self.asock
        else:
            sock = csock

        if caddr is None:
            dest = self.boxer_addr
        else:
            dest = caddr

        await self.debug_file.write(
            f"sending {obj} to {dest}.\n"
            )

        await sock.sendto(
            data,
            dest
            )

    async def rpc(
        self,
        method,
        params,
        csock=None,
        caddr=None,
        cbox=None
            ):

        pid = self.pcktidmngr.getid()

        async with self.inbound.subscribe(
            optional_decrypt_id_matcher,
            args=[
                pid,
                cbox,
                caddr if caddr is not None else self.boxer_addr
                ]
                ) as sub_queue:

            await self.send_json(
                {
                    "jsonrpc": "2.0",
                    "method": method,
                    "params": params,
                    "id": pid
                    },
                csock=csock,
                caddr=caddr,
                cbox=cbox
                )

            resp, addr = await sub_queue.receive()
            await self.debug_file.write(
                f"received {resp} from {caddr if caddr is not None else self.boxer_addr}.\n"
                )
            return resp

    async def inbound_generator(self):
        with trio.CancelScope() as self.inbound_cscope:
            while True:
                data, addr = await self.asock.recvfrom(
                    BoxerServer.BOX_MAX_PACKET_LENGTH
                    )

                if hasattr(self, "box"):
                    try:
                        data = self.box.decrypt(data)

                    except Exception as e:
                        await self.debug_file.write(
                            f"unknown: {(data, addr)}"
                            )
                        continue

                obj = json.loads(data.decode("utf-8"))
                await self.debug_file.write(
                    f"recieved {obj} from {addr}.\n"
                    )

                await self.inbound.send((obj, addr))

    async def event_listener(self):
        with trio.CancelScope() as self.listener_cscope:
            async with self.inbound.subscribe(
                method_matcher,
                args=["event", self.boxer_addr]
                    ) as event_queue:
                while True:
                    event, addr = await event_queue.receive()

                    await self.debug_file.write(
                        f"recieved event {event} from server.\n"
                        )

                    etype = event["params"]["type"]
                    key = event["params"]["pkey"]

                    if etype == "introduction":
                        self.node_directory[key] = {
                            "name": event["params"]["name"]
                        }
                        if "desc" in event["params"]:
                            self.node_directory[key]["desc"] = event["params"]

                    elif etype == "goodbye":
                        del self.node_directory[key]

    async def _bg_fight(self, nkey, fid):
        nsock = trio.socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        await self.send_json(
            {
                "jsonrpc": "2.0",
                "method": "key-ex",
                "params": {
                    "pkey": bytes(self.key.public_key).hex()
                    },
                "id": self.pcktidmngr.getid()
                },
            csock=nsock,
            cbox=False
            )

        resp, addr = await nsock.recvfrom(
            BoxerServer.BOX_MAX_PACKET_LENGTH
            )

        assert addr == self.boxer_addr

        resp = json.loads(resp.decode("utf-8"))

        assert "result" in resp

        await self.send_json(
            {
                "jsonrpc": "2.0",
                "method": "punch",
                "params": {
                    "fid": fid
                    },
                "id": self.pcktidmngr.getid()
                },
            csock=nsock
            )

        enc_resp, addr = await nsock.recvfrom(
            BoxerServer.BOX_MAX_PACKET_LENGTH
            )

        assert addr == self.boxer_addr

        resp = json.loads(
            self.box.decrypt(enc_resp)
                .decode("utf-8")
            )

        assert "result" in resp

        result = resp["result"]

        remote_addr = (
            result["host"],
            result["port"]
            )

        remote_box = Box(
            self.key,
            PublicKey(bytes.fromhex(nkey))
            )

        await self.debug_file.write(
            f"fight begin, sending to {remote_addr}\n"
            )

        for x in range(2):
            await nsock.sendto(
                remote_box.encrypt(b"punch"),
                remote_addr
                )

        with trio.move_on_after(5):
            punched_trough = False

            while True:
                enc_data, addr = await nsock.recvfrom(
                    BoxerServer.BOX_MAX_PACKET_LENGTH
                    )

                msg = remote_box.decrypt(enc_data)

                assert msg == b"punch"
                punched_trough = True
                break

        if punched_trough:
            await self.debug_file.write(
                f"fight end, punch through\n"
                )
            print(f"new remote p2p with {remote_addr}")
            await self.connections.send(
                (remote_addr, remote_box, nsock)
                )

        else:
            await self.debug_file.write(
                f"fight end, didn't punched through\n"
                )

    async def fighter(self):
        with trio.CancelScope() as self.fighter_cscope:
            async with self.inbound.subscribe(
                method_matcher,
                args=["fight", self.boxer_addr]
                    ) as fight_queue:
                while True:
                    freq, addr = await fight_queue.receive()

                    await self.debug_file.write(
                        f"recieved fight req from {freq['params']['with']}.\n"
                        )

                    if self.evade_fights:
                        result = "evade"
                    else:
                        result = "take"
                        self.nursery.start_soon(
                            self._bg_fight,
                            freq["params"]["with"],
                            freq["params"]["fid"]
                            )

                    await self.send_json(
                        {
                            "jsonrpc": "2.0",
                            "result": result,
                            "id": freq["id"]
                            }
                        )

    async def introduce(self):

        self.debug_file = await trio.open_file("bn_debug", "w")

        # generates json rpc objs from raw socket
        self.nursery.start_soon(
            self.inbound_generator
            )

        # updates node directory recieving events
        self.nursery.start_soon(
            self.event_listener
            )

        # responds to fight requests
        self.nursery.start_soon(
            self.fighter
            )

        # perform key exchange
        pid = self.pcktidmngr.getid()
        resp = await self.rpc(
            "key-ex",
            {
                "pkey": bytes(self.key.public_key).hex()
                }
            )

        self.box = Box(
            self.key,
            PublicKey(bytes.fromhex(resp["result"]))
            )

        # introduce ourselves
        params = {
            "name": self.name
        }
        if self.desc != "":
            params["desc"] = self.desc

        if self.secret:
            params["secret"] = {}

        resp = await self.rpc(
            "introduction",
            params
            )

        assert resp["result"] == "ok"

    async def fight(self, pkey):
        resp = await self.rpc(
            "fight",
            {
                "target": pkey
                }
            )

        if resp["result"] == "evade":
            return None

        self.nursery.start_soon(
            self._bg_fight,
            pkey,
            resp["result"]
            )

    async def goodbye(self):

        resp = await self.rpc("goodbye", {})
        assert resp["result"] == "goodbye"

        self.fighter_cscope.cancel()
        self.listener_cscope.cancel()
        self.inbound_cscope.cancel()

        self.asock.close()
