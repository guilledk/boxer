#!/usr/bin/env python3

import trio
import socket

from boxer.node import BoxerNode


async def packet_printer(sock, box):

    while True:
        enc_msg, addr = await sock.recvfrom(1024)
        msg = box.decrypt(enc_msg)
        print(f"recieved {msg} from {addr}")


async def main():

    async with trio.open_nursery() as nursery:

        bnode = BoxerNode(
            socket.gethostname(),
            nursery
            )

        await bnode.introduce()

        if bnode.name != "raspberrypi":
            while True:
                await trio.sleep(0.1)
                if len(bnode.node_directory) == 1:
                    print(bnode.node_directory)
                    break

            rpi = ""
            for key, node in bnode.node_directory.items():
                if node["name"] == "raspberrypi":
                    rpi = key

            await bnode.fight(rpi)

        remote_addr, remote_box, remote_sock = await bnode.connections.receive()

        nursery.start_soon(
            packet_printer,
            remote_sock,
            remote_box
            )

        for x in range(10):
            await remote_sock.sendto(
                remote_box.encrypt(
                    f"hello from peer! - {x}".encode("utf-8")
                    ),
                remote_addr
                )

        try:
            await trio.sleep_forever()
        except KeyboardInterrupt:
            pass
        finally:
            await bnode.goodbye()

trio.run(main)
