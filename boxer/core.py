#!/usr/bin/env python3

import json
import trio
import socket

from nacl.public import PublicKey, PrivateKey, Box

from aplutils import AsyncQueue, SessionIDManager


def addr_has_str(addr):
    assert len(addr) == 2
    return f"{addr[0]}:{addr[1]}"


# matches id field from a json obj
def id_matcher(*args):
    obj = args[0]
    uid = args[1]
    try:
        assert isinstance(obj, dict)
        assert obj is not None
        assert "id" in obj
        assert str(uid) == obj["id"]
        return True
    except AssertionError:
        return False


def attempt_decrypt_match_id(*args):
    tpl = args[0]
    uid = args[1]
    box = args[2]
    try:
        assert tpl is not None
        assert len(tpl) == 2
        obj = json.loads(
            box.decrypt(tpl[0]).decode("utf-8")
            )
        assert "id" in obj
        assert str(uid) == obj["id"]
        return True
    except AssertionError:
        return False


# matches first element of tuple as hex encoded pkey
def pkey_matcher(*args):
    obj = args[0]
    key = args[1]
    try:
        assert obj[0] == key
        return True
    except AssertionError:
        return False


class BoxerRemoteNode:

    def __init__(
        self,
        key,
        server,
        secret=False
            ):

        self.key = key
        self.server = server
        self.secret = secret

        self.box = Box(self.server.key, self.key)
        self.inbound = AsyncQueue()
        self.event_queue = AsyncQueue()
        self.pcktidmngr = SessionIDManager()

        self.methods = {}

        self.methods["fight"] = self.boxer_fight
        self.methods["punch"] = self.boxer_punch
        self.methods["goodbye"] = self.boxer_goodbye

    def start(self):
        self.server.nursery.start_soon(
            self.session_consumer
            )

    def stop(self):
        if hasattr(self, "session_cscope"):
            self.session_cscope.cancel()

        if hasattr(self, "event_cscope"):
            self.event_cscope.cancel()

    async def send_json(self, obj, encrypted=True, caddr=None):
        await self.server.debug_file.write(f"sending {obj} to {caddr if caddr is not None else self.main_com}.\n")
        if encrypted:
            data = self.box.encrypt(
                json.dumps(obj)
                    .encode("utf-8")
                )
        else:
            data = json.dumps(obj).encode("utf-8")

        await self.server.asock.sendto(
            data,
            caddr if caddr is not None else self.main_com
            )

    async def rpc(self, method, params, encrypted=True):
        pid = self.pcktidmngr.getid()

        async with self.inbound.subscribe(
            attempt_decrypt_match_id,
            args=[pid, self.box]
                ) as sub_queue:

            await self.send_json(
                {
                    "jsonrpc": "2.0",
                    "method": method,
                    "params": params,
                    "id": pid
                    }
                )

            enc_resp, addr = await sub_queue.receive()
            return json.loads(
                self.box.decrypt(enc_resp)
                    .decode("utf-8")
                )

    async def event_consumer(self):
        await self.server.debug_file.write(f"started event consumer for {self.main_com}.\n")
        with trio.CancelScope() as self.event_cscope:
            while True:
                event = await self.event_queue.receive()

                await self.send_json(
                    {
                        "jsonrpc": "2.0",
                        "method": "event",
                        "params": event,
                        "id": self.pcktidmngr.getid()
                        }
                    )

    async def session_consumer(self):

        # next msg should be encrypted introduction
        enc_msg, addr = await self.inbound.receive()
        self.main_com = addr
        msg = json.loads(
            self.box.decrypt(enc_msg)
                .decode("utf-8")
            )

        await self.server.debug_file.write(f"{msg} from {addr}.\n")

        assert "jsonrpc" in msg
        assert "method" in msg
        assert "params" in msg
        assert "id" in msg

        params = msg["params"]

        assert msg["method"] == "introduction"

        assert "name" in params

        self.name = params["name"]

        if "desc" in params:
            self.desc = params["desc"]

        if "secret" in params:
            assert params["secret"] is {}
            self.secret = True

        await self.send_json(
            {
                "jsonrpc": "2.0",
                "result": "ok",
                "id": msg["id"]
                }
            )

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

            print(f"new node introduced: {bytes(self.key).hex()}")

        # send node directory as introduction events
        nodes = [
            item for item in self.server.nodes.items()
            if item[0] != self.key
        ]
        for nkey, node in nodes:

            # check if node has been introduced
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

        self.server.nursery.start_soon(
            self.event_consumer
            )

        with trio.CancelScope() as self.session_cscope:

            while True:

                enc_msg, addr = await self.inbound.receive()

                msg = json.loads(
                    self.box.decrypt(enc_msg)
                        .decode("utf-8")
                    )

                await self.server.debug_file.write(f"{msg} from {addr}.\n")

                assert "jsonrpc" in msg
                assert "method" in msg
                assert "params" in msg
                assert "id" in msg

                method = msg["method"]
                params = msg["params"]
                id = msg["id"]

                if method in self.methods:
                    self.server.nursery.start_soon(
                        self.methods[method],
                        params,
                        addr,
                        id
                        )
                else:
                    self.server.nursery.start_soon(
                        self.send_json,
                        {
                            "jsonrpc": "2.0",
                            "error": {
                                "code": "0",
                                "message": "protocol error"
                            },
                            "id": id
                            }
                        )

    # boxer methods

    async def boxer_goodbye(self, params, address, id):

        # clean up opened entry points
        cleanup_addrs = [
            addr for addr, key in self.server.addr_key_table.items()
            if key == bytes(self.key).hex()
            ]
        for addr in cleanup_addrs:
            self.server.unregister_addr(addr)

        self.stop()

        del self.server.nodes[self.key]

        if not self.secret:
            await self.server.broadcast(
                {
                    "type": "goodbye",
                    "pkey": bytes(self.key).hex()
                    },
                self
                )

        await self.send_json(
            {
                "jsonrpc": "2.0",
                "result": "goodbye",
                "id": id
                }
            )

    async def boxer_fight(self, params, address, id):

        assert "target" in params

        tkey = PublicKey(bytes.fromhex(params["target"]))

        if tkey not in self.server.nodes:
            await self.send_json(
                {
                    "jsonrpc": "2.0",
                    "error": {
                        "code": "1",
                        "message": "node not found"
                    },
                    "id": id
                    }
                )

        else:

            target_node = self.server.nodes[tkey]

            fid = self.server.fightidmngr.getid()

            resp = await target_node.rpc(
                "fight",
                {
                    "with": bytes(self.key).hex(),
                    "fid": fid
                    }
                )

            result = resp["result"]
            if result == "take":
                self.server.fights[fid] = {
                    "a": bytes(self.key).hex(),
                    "b": tkey,
                    "addrs": []
                    }
                result = fid

            await self.send_json(
                {
                    "jsonrpc": "2.0",
                    "result": result,
                    "id": id
                    }
                )

    async def boxer_punch(self, params, address, id):

        assert "fid" in params

        fid = params["fid"]
        fight = self.server.fights[fid]
        fight["addrs"].append(
            (bytes(self.key).hex(), address)
            )

        if len(fight["addrs"]) == 2:
            node0_pkey, node0_naddr = fight["addrs"][0]
            node0 = self.server.nodes[PublicKey(bytes.fromhex(node0_pkey))]
            node1_pkey, node1_naddr = fight["addrs"][1]
            node1 = self.server.nodes[PublicKey(bytes.fromhex(node1_pkey))]

            self.server.nursery.start_soon(
                self.server.asock.sendto,
                node0.box.encrypt(
                    json.dumps(
                        {
                            "jsonrpc": "2.0",
                            "result": {
                                "host": node1_naddr[0],
                                "port": node1_naddr[1]
                                },
                            "id": node0.pcktidmngr.getid()
                            }
                        ).encode("utf-8")
                    ),
                node0_naddr
                )

            self.server.nursery.start_soon(
                self.server.asock.sendto,
                node1.box.encrypt(
                    json.dumps(
                        {
                            "jsonrpc": "2.0",
                            "result": {
                                "host": node0_naddr[0],
                                "port": node0_naddr[1]
                                },
                            "id": node1.pcktidmngr.getid()
                            }
                        ).encode("utf-8")
                    ),
                node1_naddr
                )


class BoxerServer:

    BOX_VERSION = "0.1.0"
    BOX_MAX_PACKET_LENGTH = 4096

    def __init__(
        self,
        nursery,
        host="0.0.0.0",
        port=12000
            ):

        self.nursery = nursery
        self.host = host
        self.port = port

        self.key = PrivateKey.generate()
        self.asock = trio.socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.nodes = {}
        self.addr_key_table = {}

        self.fights = {}
        self.fightidmngr = SessionIDManager()

    async def init(self):

        self.debug_file = await trio.open_file("bs_debug", "w")

        print(f"boxer server v{BoxerServer.BOX_VERSION} init...")
        print(f"{bytes(self.key.public_key).hex()}")

        await self.asock.bind((self.host, self.port))

        print(f"socket binded on {self.host}:{self.port}")

        self.nursery.start_soon(
            self.inbound_generator
            )

    def stop(self):
        print("stopping boxer server...")
        for key, node in self.nodes.items():
            node.stop()
        print("boxer server stopped")

    def register_new_addr(self, addr, key):
        self.addr_key_table[addr_has_str(addr)] = key

    def unregister_addr(self, addr):
        if not isinstance(addr, str):
            addr = addr_has_str(addr)
        del self.addr_key_table[addr]

    async def _bg_key_exchange(self, data, address):

        msg = json.loads(data.decode("utf-8"))

        await self.debug_file.write(f"{msg} from {address}.\n")

        assert "jsonrpc" in msg
        assert "method" in msg
        assert "params" in msg
        assert "id" in msg

        assert msg["jsonrpc"] == "2.0"
        assert msg["method"] == "key-ex"
        assert "pkey" in msg["params"]

        nkey = msg["params"]["pkey"]

        nkey = PublicKey(bytes.fromhex(nkey))

        self.register_new_addr(address, nkey)

        if nkey not in self.nodes:
            self.nodes[nkey] = BoxerRemoteNode(
                nkey,
                self
                )
            self.nodes[nkey].start()

        await self.nodes[nkey].send_json(
            {
                "jsonrpc": "2.0",
                "result": bytes(self.key.public_key).hex(),
                "id": msg["id"]
                },
            encrypted=False,
            caddr=address
            )

    async def broadcast(self, event, orig):
        print(f"broadcasting {event['type']}")
        nodes = [item for item in self.nodes.values() if item != orig]
        for node in nodes:
            await node.event_queue.send(event)

    async def inbound_generator(self):

        self.inbound_cscope = trio.CancelScope()
        with self.inbound_cscope:

            while True:

                data, address = await self.asock.recvfrom(
                    BoxerServer.BOX_MAX_PACKET_LENGTH
                    )

                if addr_has_str(address) not in self.addr_key_table:
                    print(f"new addr conected {address}")
                    self.nursery.start_soon(
                        self._bg_key_exchange,
                        data,
                        address
                        )

                else:

                    pkey = self.addr_key_table[addr_has_str(address)]
                    await self.nodes[pkey].inbound.send((data, address))


async def main():

    async with trio.open_nursery() as nursery:

        server = BoxerServer(nursery)

        await server.init()

        try:
            await trio.sleep_forever()
        finally:
            server.stop()

if __name__ == '__main__':
    try:
        trio.run(main)
    except KeyboardInterrupt:
        pass
