import unittest
from unittest.mock import MagicMock, Mock

import asyncio
from Peer import *
from test_Messages import validMessages


def AsyncMock(*args, **kwargs):
    m = MagicMock(*args, **kwargs)

    async def mock_coro(*args, **kwargs):
        return m(*args, **kwargs)

    mock_coro.mock = m
    return mock_coro


async def read_all(peer):
    l = []
    async for m in peer.read():
        l.append(m)
    return l


class TestMessageReading(unittest.TestCase):
    def test_read(self):
        """Test the read() method of the Peer class

        reader.read() passes to Peer.read() a bytestring containing a series of messages.
        Peer.read() must decode each message
        """
        bytes, messages = map(list, zip(*(validMessages.items())))

        bytestring = b"".join(bytes)

        reader = Mock()
        reader.read = AsyncMock(return_value=bytestring)
        reader.at_eof = MagicMock(return_value=True)
        writer = Mock()
        writer.get_extra_info = MagicMock(return_value=("127.0.0.1", 9000))

        loop = asyncio.new_event_loop()

        p = Peer()
        p.connect(loop, reader=reader, writer=writer)
        result = loop.run_until_complete(read_all(p))
        loop.close()

        for i, message in enumerate(messages):
            with self.subTest(case=bytes[i], expected=message, result=result[i]):
                self.assertEqual(result[i], message)


if __name__ == '__main__':
        unittest.main()
