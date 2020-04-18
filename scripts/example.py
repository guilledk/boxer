#!/usr/bin/env python3

import trio
import logging

from boxer.node import BoxerNode


async def sender_service(remote_ctx):
    x = 1
    while True:
        await remote_ctx.send_raw(
            f"hello from peer! - {x}".encode("utf-8")
            )
        await trio.sleep(1)
        x += 1


async def main():

    logging.basicConfig(
            level=logging.DEBUG,
            format='%(message)s'
            )

    async with trio.open_nursery() as nursery:

        bnode = BoxerNode(
            ("127.0.0.1", 12000),  # server addresss
            nursery
            )

        await bnode.introduction(
            "my_name",
            secret=False
            )

        try:
            async with bnode.events.subscribe(
                lambda *args: args[0]["name"] == "my_name"
                    ) as event_queue:

                event = await event_queue.receive()

            remote_ctx = await bnode.fight(event["pkey"])

            nursery.start_soon(
                sender_service,
                remote_ctx
                )

            async with remote_ctx.inbound.subscribe(
                lambda *args: True,
                history=True
                    ) as in_queue:
                while True:
                    msg = await in_queue.receive()
                    print(f"recieved {msg} from {repr(remote_ctx)}")

        except KeyboardInterrupt:
            pass

        finally:
            await bnode.goodbye()

trio.run(main)
