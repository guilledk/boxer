![](logo.png)

### Features

- Fast UDP hole punching
- Public Key based peer directory, with service descriptions
- Ed25519 encrypted
- `jsonrpc 2.0`
- Fully async (trio v0.13)
- Python 3

#### Dependencies

- ![trio](https://github.com/python-trio/trio)
- ![triopatterns](https://github.com/guilledk/triopatterns)
- pynacl

#### Install

Download this repo and cd into it.

`pip install .`

#### Run Server

`python -m boxer.core`

#### Boxer Protocol

Boxer is simple UDP hole punching protocol:

https://github.com/dwoz/python-nat-hole-punching
https://bford.info/pub/net/p2pnat/

A Boxer server listens from incoming node "introductions" and broadcasts them to all conected nodes, based on their public key nodes can request "fights" where the server arranges for the exchange of external endpoint information between nodes and then through "punch" packets perform NAT traversal.

Look at ![PROTOCOL.txt](PROTOCOL.txt) for more information.

#### Boxer Node API

```python
import trio

from boxer.node import BoxerNode


async def main():

    # Boxer makes heavy use of the trio async framework, when instantiating a
    # BoxerNode instance we must provide a `trio.Nursery` instance
    async def trio.open_nursery() as nursery:

        bnode = BoxerNode(
            ("127.0.0.1", 12000),  # boxer server addresss
            nursery
            )

        await bnode.introduction(
            "my_name",  # non unique name
            desc="my description"  # optional description
            )

        # get next node introduction event
        event = await bnode.events.receive()

        # to INITIATE fights:
        remote_ctx = await bnode.fight(event["pkey"])

        # to TAKE fights:
        fid, remote_ctx = await bnode.fights.receive()

        # remote context is a boxer.net.UDPContext instance
        # non connection with remote peer is open

        await remote_ctx.send_raw(b"hello from peer!")

        # to recieve messages use remote context inbound queue
        async with remote_ctx.inbound.subscribe(
            lambda *args: True
                ) as in_queue:

            msg = await in_queue.receive()
```