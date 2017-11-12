from unittest import TestCase
from unittest.mock import MagicMock, Mock

import asyncio
from Peer import *
from test_Messages import validMessages


class TestMessageReading(TestCase):
    def test_read(self):
        bytestring = b"".join(validMessages.keys())


