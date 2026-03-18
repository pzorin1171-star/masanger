import asyncio
import socks

async def open_tor_connection(host, port,
                              tor_host='127.0.0.1', tor_port=9050):
    """Подключение к серверу через SOCKS5-прокси Tor."""
    loop = asyncio.get_running_loop()
    s = socks.socksocket()
    s.set_proxy(socks.SOCKS5, tor_host, tor_port)
    s.setblocking(False)
    try:
        await loop.sock_connect(s, (host, port))
    except Exception:
        s.close()
        raise

    reader = asyncio.StreamReader(loop=loop)
    protocol = asyncio.StreamReaderProtocol(reader)
    transport, _ = await loop.create_connection(lambda: protocol, sock=s)
    writer = asyncio.StreamWriter(transport, protocol, reader, loop)
    return reader, writer
