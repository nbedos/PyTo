from unittest import TestCase
import unittest.mock
import asyncio
import PyTo
import logging
from tempfile import mkdtemp
from shutil import copy, rmtree


class TestLocalDownload(TestCase):
    """Test PyTo on the loopback interface.

    The Torrent.get_peers method is mocked to avoid using a tracker"""
    def test_2_instances(self):
        logging.basicConfig(format='%(asctime)s %(message)s', level=logging.DEBUG)
        loop = asyncio.get_event_loop()

        # First instance of PyTo (seeder)
        dir1 = mkdtemp()
        copy("./data/files/lorem.txt", dir1)
        with unittest.mock.patch.object(PyTo.Torrent, 'get_peers') as get_peers_mocked:
            get_peers_mocked.return_value = []
            c1 = PyTo.download(loop, "./data/torrent files/lorem.txt.torrent",
                               6881, dir1)

        # Second instance of PyTo (leecher)
        dir2 = mkdtemp()
        with unittest.mock.patch.object(PyTo.Torrent, 'get_peers') as get_peers_mocked:
            get_peers_mocked.return_value = [("127.0.0.1", 6881)]
            c2 = PyTo.download(loop, "./data/torrent files/lorem.txt.torrent",
                               6882, dir2)

        loop.run_until_complete(asyncio.gather(*(c1 + c2)))

        loop.close()
        rmtree(dir1)
        rmtree(dir2)

