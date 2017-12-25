import asyncio
import concurrent.futures
import datetime
import filecmp
import unittest.mock
import logging
import os
from shutil import copy, rmtree
from tempfile import mkdtemp
from unittest import TestCase
from typing import List

from pyto.torrent import Torrent, init, download
from pyto.peer import Peer

TEST_FILE_DIR = os.path.dirname(os.path.abspath(__file__))
# DATA_DIR is TEST_FILE_DIR/data 
DATA_DIR = os.path.join(TEST_FILE_DIR, 'data')


class TestLocalDownload(TestCase):
    """Test PyTo on the loopback interface.

    The Torrent.get_peers method is mocked to avoid using a tracker"""
    def test_2_instances(self):
        logging.basicConfig(
            level=logging.DEBUG,
            format="[%(asctime)s] %(levelname)s [%(name)s.%(funcName)s:%(lineno)d]@%(threadName)s "
                   "%(message)s",
            datefmt="%H:%M:%S")

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        loop.set_debug(False)
        executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        loop.set_default_executor(executor)

        dir1 = mkdtemp()
        dir2 = mkdtemp()

        # Setup a directory and files for the seeder
        copy(os.path.join(DATA_DIR, "files", "lorem.txt"), dir1)

        torrent_file = os.path.join(DATA_DIR, "torrent files", "lorem.txt.torrent")
        torrent_seeder = init(torrent_file, dir1)
        torrent_leecher = init(torrent_file, dir2)

        async def seeder():
            with unittest.mock.patch.object(Torrent, 'get_peers') as get_peers_mocked:
                # Mock Torrent.get_peers to return an empty list
                get_peers_mocked.return_value = []
                await download(torrent_seeder, 6881)

        async def leecher():
            with unittest.mock.patch.object(Torrent, 'get_peers') as get_peers_mocked:
                # Mock Torrent.get_peers to return the address of the seeder
                get_peers_mocked.return_value = [("127.0.0.1", 6881)]
                # Setup a directory and files for the leecher
                await download(torrent_leecher, 6882)

        async def wait_for(torrent: Torrent, events: List[str]):
            event = None
            while event not in events:
                event = await torrent.queue.get()
            return event

        # Futures
        f_seeder = asyncio.ensure_future(seeder())
        f_wait_accept_conns = asyncio.ensure_future(
            wait_for(torrent_seeder, ["EVENT_ACCEPT_CONNECTIONS", "EVENT_END"])
        )
        f_leecher = None
        f_download_complete = None

        futures = {f_seeder, f_wait_accept_conns}
        while futures:
            done, futures = loop.run_until_complete(
                asyncio.wait(futures, return_when=asyncio.FIRST_COMPLETED)
            )

            for item in done:
                result = item.result()

                # Once the seeder accepts connection, start the leecher and wait for it to complete
                # the download
                if item == f_wait_accept_conns:
                    if result == "EVENT_ACCEPT_CONNECTIONS":
                        f_leecher = asyncio.ensure_future(leecher(), loop=loop)
                        f_download_complete = asyncio.ensure_future(
                            wait_for(torrent_leecher, ["EVENT_DOWNLOAD_COMPLETE", "EVENT_END"])
                        )
                        futures = futures | {f_leecher, f_download_complete}
                    elif result == "EVENT_END":
                        print("leecher failed")

                # Once the leecher has downloaded the file, stop all torrents
                if item == f_download_complete:
                    if result == "EVENT_DOWNLOAD_COMPLETE":
                        torrent_leecher.stop()
                        torrent_seeder.stop()
                    elif result == "EVENT_END":
                        print("seeder failed")

        loop.stop()
        loop.close()

        file_seeder = os.path.join(dir1, "lorem.txt")
        file_leecher = os.path.join(dir2, "lorem.txt")

        print("Comparing:")
        print("   - {}".format(file_seeder))
        print("   - {}".format(file_leecher))
        self.assertTrue(filecmp.cmp(file_seeder, file_leecher, False))


if __name__ == '__main__':
        unittest.main()
