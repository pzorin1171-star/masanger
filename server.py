import asyncio
import logging
import os
import json
from aiohttp import web, WSMsgType

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("server")

# Хранилище подключений: websocket -> {name, pubkey_der}
clients = {}

async def websocket_handler(request):
    ws = web.WebSocketResponse()
    await ws.prepare(request)

    peer = request.remote
    logger.info(f"New WebSocket connection from {peer}")

    try:
        # Ждём регистрационное сообщение (JSON с name и pubkey_der в base64)
        msg = await ws.receive_json()
        if msg.get('type') != 'register':
            await ws.close()
            return ws

        name = msg['name']
        pubkey_der = bytes.fromhex(msg['pubkey_hex'])  # передаём hex для простоты

        clients[ws] = {'name': name, 'pubkey_der': pubkey_der}
        logger.info(f"Client registered: {name}")

        # Оповестить остальных о новом пользователе
        await broadcast_user_info(ws, name, pubkey_der)

        # Основной цикл приёма сообщений
        async for msg in ws:
            if msg.type == WSMsgType.TEXT:
                data = json.loads(msg.data)
                if data.get('type') == 'message':
                    encrypted_hex = data['encrypted']
                    await broadcast_message(ws, encrypted_hex)
            elif msg.type == WSMsgType.ERROR:
                logger.error(f"WebSocket error: {ws.exception()}")

    except Exception as e:
        logger.error(f"Error: {e}")
    finally:
        # Удаляем клиента при отключении
        if ws in clients:
            del clients[ws]
        logger.info(f"Client {peer} disconnected")
    return ws

async def broadcast_user_info(sender_ws, name, pubkey_der):
    """Отправить всем, кроме отправителя, информацию о новом пользователе"""
    msg = json.dumps({
        'type': 'new_user',
        'name': name,
        'pubkey_hex': pubkey_der.hex()
    })
    for ws, info in clients.items():
        if ws != sender_ws:
            try:
                await ws.send_str(msg)
            except:
                pass

async def broadcast_message(sender_ws, encrypted_hex):
    """Переслать зашифрованное сообщение всем, кроме отправителя"""
    msg = json.dumps({
        'type': 'message',
        'encrypted': encrypted_hex
    })
    for ws, info in clients.items():
        if ws != sender_ws:
            try:
                await ws.send_str(msg)
            except:
                pass

async def health_check(request):
    return web.Response(text="OK")

def main():
    app = web.Application()
    app.router.add_get('/', health_check)      # для проверки здоровья Render
    app.router.add_get('/ws', websocket_handler)

    port = int(os.environ.get('PORT', 8080))
    logger.info(f"Starting server on port {port}")
    web.run_app(app, port=port)

if __name__ == '__main__':
    main()
