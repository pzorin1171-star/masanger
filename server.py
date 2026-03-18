import asyncio
import logging
import os
from collections import namedtuple

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("server")

Client = namedtuple('Client', ['reader', 'writer', 'name', 'pubkey_der'])

class Server:
    def __init__(self, host='0.0.0.0', port=8888):
        self.host = host
        self.port = int(os.getenv('PORT', port))
        self.clients = {}  # writer -> Client

    async def handle_client(self, reader, writer):
        peer = writer.get_extra_info('peername')
        logger.info(f"New connection from {peer}")

        try:
            # Регистрация: имя и публичный ключ
            data = await reader.readexactly(4)
            name_len = int.from_bytes(data, 'big')
            name = (await reader.readexactly(name_len)).decode('utf-8')

            data = await reader.readexactly(4)
            key_len = int.from_bytes(data, 'big')
            pubkey_der = await reader.readexactly(key_len)

            logger.info(f"Client registered: {name}")

            client = Client(reader, writer, name, pubkey_der)
            self.clients[writer] = client

            # Оповестить остальных о новом пользователе
            await self._broadcast_user_info(client, exclude=writer)

            # Цикл приёма сообщений
            while True:
                data = await reader.readexactly(4)
                msg_len = int.from_bytes(data, 'big')
                if msg_len == 0:
                    break
                msg_data = await reader.readexactly(msg_len)
                await self._broadcast_message(msg_data, sender=writer)

        except (asyncio.IncompleteReadError, ConnectionResetError):
            logger.info(f"Client {peer} disconnected")
        finally:
            if writer in self.clients:
                del self.clients[writer]
            writer.close()
            await writer.wait_closed()

    async def _broadcast_user_info(self, new_client, exclude=None):
        name_bytes = new_client.name.encode('utf-8')
        msg = (b'\x01' +
               len(name_bytes).to_bytes(4, 'big') + name_bytes +
               len(new_client.pubkey_der).to_bytes(4, 'big') + new_client.pubkey_der)
        for w, client in self.clients.items():
            if w == exclude:
                continue
            try:
                w.write(len(msg).to_bytes(4, 'big') + msg)
                await w.drain()
            except Exception as e:
                logger.error(f"Error sending to {client.name}: {e}")

    async def _broadcast_message(self, encrypted_msg, sender=None):
        msg = b'\x02' + encrypted_msg
        for w, client in self.clients.items():
            if w == sender:
                continue
            try:
                w.write(len(msg).to_bytes(4, 'big') + msg)
                await w.drain()
            except Exception as e:
                logger.error(f"Error sending to {client.name}: {e}")

    async def run(self):
        server = await asyncio.start_server(self.handle_client,
                                            self.host, self.port)
        logger.info(f"Server listening on {self.host}:{self.port}")
        async with server:
            await server.serve_forever()

if __name__ == '__main__':
    server = Server()
    asyncio.run(server.run())
