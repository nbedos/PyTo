import unittest
import socket

import asyncio
from Peer import Peer
from test_Messages import VALID_MESSAGES, VALID_HANDSHAKE


class TestPeer(unittest.TestCase):
    def test_connect(self):
        """Test Peer.connect()"""
        ip = "127.0.0.1"
        port = 6991
        loop = asyncio.get_event_loop()
        event = asyncio.Event()

        async def server():
            """Create a listening socket and accept the first connection"""
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.setblocking(0)
            server_socket.bind(('', 6991))
            server_socket.listen(5)
            event.set()
            client_socket, _ = await loop.sock_accept(server_socket)
            client_socket.close()
            server_socket.close()

        async def client():
            """Once the server is listening, connect the peer"""
            p = Peer()
            await event.wait()
            await p.connect(loop, ip, port)
            p.close()

        f_server = asyncio.ensure_future(server())
        f_peer = asyncio.ensure_future(client())

        futures = asyncio.gather(f_server, f_peer)
        loop.run_until_complete(futures)

    def _test_get_messages(self, buffer_size):
        """Test that a list of messages are correctly decoded"""
        loop = asyncio.get_event_loop()

        # Setup for the Peer instance
        p = Peer()
        p.socket, remote_socket = socket.socketpair()
        p.buffer_size = buffer_size

        # Coroutine #1: send all messages to the peer
        async def send(s: socket.socket, b: bytes):
            loop.sock_sendall(s, b)
            s.close()

        # Coroutine #2: read all the messages sent on the socket
        async def get_all_messages(peer: Peer):
            return [m async for m in peer.get_messages()]

        # Reuse a list of messages from test_Messages
        all_messages = []
        for bytes_message, message in VALID_HANDSHAKE.items():
            all_messages.append((bytes_message, message))
        for (length, payload), message in VALID_MESSAGES.items():
            all_messages.append((b"".join([length, payload]), message))
        bytes_messages, messages = map(list, zip(*all_messages))
        bytestring = b"".join(bytes_messages)

        # Create futures
        f_remote = asyncio.ensure_future(send(remote_socket, bytestring))
        f_peer = asyncio.ensure_future(get_all_messages(p))
        futures = asyncio.gather(f_remote, f_peer)
        # results[0] = result from f_remote
        # results[1] = result from f_peer
        results = loop.run_until_complete(futures)
        result = results[1]

        # Check that each decoded message is identical to the original message
        for i, message in enumerate(messages):
            name = "buffer_size={}".format(buffer_size)
            with self.subTest(name=name,
                              case=bytes_messages[i],
                              expected=message,
                              result=result[i]):
                self.assertEqual(result[i], message)

    def test_get_messages(self):
        """Test Peer.get_messages for varying buffer sizes"""
        # Usual buffer size
        self._test_get_messages(buffer_size=4096)
        # Intermediary buffer size
        self._test_get_messages(buffer_size=5)
        # Minimal buffer size which should still work
        self._test_get_messages(buffer_size=1)


if __name__ == '__main__':
        unittest.main()
