#!/usr/bin/env python3

import trio
import socket
import logging
import argparse

from boxer.node import BoxerNode


async def main():

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-i", "--ip", type=str,
        help=f"set boxer server ip"
        )
    parser.add_argument(
        "-p", "--port", type=int,
        help=f"set boxer server port"
        )
    parser.add_argument(
        "-n", "--name", type=str,
        help=f"set a name for this node"
        )

    parser.add_argument(
        "-d", "--desc", type=str,
        help=f"set a description for this node"
        )
    parser.add_argument(
        "-f", "--fight", type=str,
        help=f"fight a node"
        )
    args = parser.parse_args()

    async with trio.open_nursery() as nursery:

        logging.basicConfig(
            level=logging.DEBUG,
            format='%(asctime)s %(message)s',
            datefmt='%d-%b-%y %H:%M:%S'
            )

        bnode = BoxerNode(
            (
                args.ip if args.ip else "127.0.0.1",
                args.port if args.port else 12000
                ),
            nursery
            )

        await bnode.introduction(
            args.name if args.name else socket.gethostname(),
            desc=args.desc if args.desc else "",
            secret=False
            )

        try:
            remote_ctx = None
            in_cscope = trio.CancelScope()

            if args.fight:
                found = False
                while not found:
                    event = await bnode.events.receive()

                    if event["name"] == args.fight:
                        found = True

                remote_ctx = await bnode.fight(event["pkey"])
            else:
                fid, remote_ctx = await bnode.fights.receive()

            async def packet_printer(remote_ctx, cscope):
                with cscope:
                    async with remote_ctx.inbound.subscribe(
                        lambda *args: True,
                        history=True
                            ) as in_queue:
                        while True:
                            msg = await in_queue.receive()
                            print(f"recieved {msg} from {repr(remote_ctx)}")

            for x in range(10):
                await remote_ctx.send_raw(
                    f"hello from peer! - {x}".encode("utf-8")
                    )

            nursery.start_soon(
                packet_printer,
                remote_ctx,
                in_cscope
                )

            await trio.sleep_forever()

        except KeyboardInterrupt:
            pass

        finally:
            in_cscope.cancel()
            if remote_ctx is not None:
                remote_ctx.stop_inbound()
            await bnode.goodbye()

trio.run(main)
