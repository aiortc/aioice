import asyncio

from aioice import stun


class StunServerProtocol(asyncio.DatagramProtocol):
    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        message = stun.parse_message(data)

        if (message.message_class == stun.Class.REQUEST and
           message.message_method == stun.Method.BINDING):
            response = stun.Message(
                message_method=message.message_method,
                message_class=stun.Class.RESPONSE,
                transaction_id=message.transaction_id)
            response.attributes['XOR-MAPPED-ADDRESS'] = addr
            self.transport.sendto(bytes(response), addr)


class StunServer:
    async def close(self):
        self.transport.close()

    async def listen(self, port=0):
        loop = asyncio.get_event_loop()
        self.transport, _ = await loop.create_datagram_endpoint(
            StunServerProtocol,
            local_addr=('127.0.0.1', port))
        self.address = self.transport.get_extra_info('sockname')
