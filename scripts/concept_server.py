#!/usr/bin/env python3

import trio
import socket


async def main():

    sock = trio.socket.socket(
        socket.AF_INET,
        socket.SOCK_DGRAM
        )

    await sock.bind(("0.0.0.0", 12000))

    addresses = []

    while True:

        msg, addr = await sock.recvfrom(1024)

        print(f"{msg} from {addr}")

        addresses.append(addr)

        if len(addresses) == 2:
            await sock.sendto(
                f"{addresses[1][0]}:{addresses[1][1]}".encode("utf-8"),
                addresses[0]
                )
            await sock.sendto(
                f"{addresses[0][0]}:{addresses[0][1]}".encode("utf-8"),
                addresses[1]
                )
            addresses.clear()

if __name__ == '__main__':
    try:
        trio.run(main)
    except KeyboardInterrupt:
        pass
