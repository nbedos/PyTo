import asyncio
import socket
import unittest

from pyto.peer import Peer
from tests.test_messages import VALID_MESSAGES, VALID_HANDSHAKE


class TestPeer(unittest.TestCase):
    def test_connect(self):
        """Test Peer.connect()"""
        ip = "127.0.0.1"
        port = 6991
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        event_server_ready = asyncio.Event()
        event_peer_disconnected = asyncio.Event()

        async def server():
            """Create a listening socket and accept the first connection"""
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.setblocking(0)
            server_socket.bind((ip, port))
            server_socket.listen(5)
            event_server_ready.set()
            client_socket, _ = await loop.sock_accept(server_socket)
            await event_peer_disconnected.wait()
            client_socket.close()
            server_socket.close()

        async def client():
            """Once the server is listening, connect the peer"""
            p = Peer(ip, port, reader=None, writer=None)
            await event_server_ready.wait()
            await p.connect()
            p.close()
            event_peer_disconnected.set()

        f_server = asyncio.ensure_future(server())
        f_peer = asyncio.ensure_future(client())

        futures = asyncio.gather(f_server, f_peer)
        loop.run_until_complete(futures)

    def test_get_messages(self):
        """Test get_messages"""
        # Create bytestring from list of messages
        all_messages = []
        for bytes_message, message in VALID_HANDSHAKE.items():
            all_messages.append((bytes_message, message))
        for (length, payload), message in VALID_MESSAGES.items():
            all_messages.append((b"".join([length, payload]), message))
        bytes_messages, messages = map(list, zip(*all_messages))
        bytestring = b"".join(bytes_messages)

        async def seeder_callback(_, w):
            w.write(bytestring)
            await w.drain()
            w.close()

        async def read_data():
            # Create server
            await asyncio.start_server(seeder_callback, "127.0.0.1", 6992)
            # Create Peer instance
            p = Peer("127.0.0.1", 6992, None, None)
            await p.connect()
            read_messages = [m async for m in p.get_messages()]
            p.close()
            return read_messages

        loop = asyncio.get_event_loop()
        results = loop.run_until_complete(read_data())
        self.assertEqual(results, messages)


if __name__ == '__main__':
        unittest.main()
