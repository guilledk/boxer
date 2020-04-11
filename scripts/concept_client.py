#!/usr/bin/env python3

import trio
import socket


server_addr = ("3.133.35.46", 12000)


async def packet_printer(sock):

    while True:
        msg, addr = await sock.recvfrom(1024)
        print(f"recieved {msg} from {addr}")


async def main():

    sock = trio.socket.socket(
        socket.AF_INET,
        socket.SOCK_DGRAM
        )

    await sock.sendto(b"\0", server_addr)

    msg, addr = await sock.recvfrom(1024)

    spl_msg = msg.decode("utf-8").split(":")
    remote_addr = (spl_msg[0], int(spl_msg[1]))

    async with trio.open_nursery() as nursery:

        nursery.start_soon(
            packet_printer,
            sock
            )

        for x in range(2):
            await sock.sendto(b"hello from peer", remote_addr)

        await trio.sleep_forever()

if __name__ == '__main__':
    try:
        trio.run(main)
    except KeyboardInterrupt:
        pass
