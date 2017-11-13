import unittest.mock
import asyncio
import logging
import concurrent.futures

from shutil import copy, rmtree
from tempfile import mkdtemp
from unittest import TestCase

from Torrent import Torrent, download


class TestLocalDownload(TestCase):
    """Test PyTo on the loopback interface.

    The Torrent.get_peers method is mocked to avoid using a tracker"""
    def test_2_instances(self):
        logging.basicConfig(
            level=logging.DEBUG,
            format="[%(asctime)s] %(levelname)s [%(name)s.%(funcName)s:%(lineno)d]@%(threadName)s "
                   "%(message)s",
            datefmt="%H:%M:%S")
        loop = asyncio.get_event_loop()
        executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        loop.set_default_executor(executor)

        # First instance of PyTo (seeder)
        dir1 = mkdtemp()
        print(dir1)
        copy("./data/files/lorem.txt", dir1)
        with unittest.mock.patch.object(Torrent, 'get_peers') as get_peers_mocked:
            get_peers_mocked.return_value = []
            c1 = download(loop, "./data/torrent files/lorem.txt.torrent",
                               6881, dir1)

        # Second instance of PyTo (leecher)
        dir2 = mkdtemp()
        with unittest.mock.patch.object(Torrent, 'get_peers') as get_peers_mocked:
            get_peers_mocked.return_value = [("127.0.0.1", 6881)]
            c2 = download(loop, "./data/torrent files/lorem.txt.torrent",
                               6882, dir2)

        loop.run_until_complete(asyncio.gather(*(c1 + c2)))

        loop.close()
        rmtree(dir1)
        rmtree(dir2)
