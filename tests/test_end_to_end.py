import asyncio
import concurrent.futures
import filecmp
import functools
import logging
import os
import shutil
import tempfile
import unittest

from typing import List

from pyto.bencoding import bencode
from pyto.torrent import Torrent, metainfo

TEST_FILE_DIR = os.path.dirname(os.path.abspath(__file__))
# DATA_DIR is TEST_FILE_DIR/data
DATA_DIR = os.path.join(TEST_FILE_DIR, 'data')


# TODO: Eventually this should be replaced by a TorrentManager class that allows the same Torrent
# (same infohash) to be downloaded simultaneously multiple times. This would only be useful
# from a testing perspective. From a user perspective you want a single Torrent instance
# by infohash (which might be updated with new trackers or peers if the Torrent is added to
# the TorrentManager from multiple sources).
def two_peer_swarm(data_dir, seeder_port=6881, leecher_port=6882):
    """ - Create a torrent file for a given directory
        - Create two Torrent instances from the file
        - Exchange data between these two instances until the leecher has downloaded the whole file
    """
    # Setup asyncio loop
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.set_debug(False)
    executor = concurrent.futures.ThreadPoolExecutor()
    loop.set_default_executor(executor)

    # Setup working directories
    tmp_dir = tempfile.mkdtemp()
    seeder_dir = os.path.join(tmp_dir, "seeder")
    leecher_dir = os.path.join(tmp_dir, "leecher")
    # The seeder's directory is initiated with all the files
    shutil.copytree(data_dir, seeder_dir)
    # The leecher's directory is empty
    os.makedirs(leecher_dir, exist_ok=True)

    # Create metainfo file on disk on the fly
    torrent_file = os.path.join(tmp_dir, 'metainfo.torrent')
    m = metainfo(data_dir, 32768, [['http://www.example.com/announce']])
    with open(torrent_file, 'wb') as f:
        f.write(bencode(m))

    async def mock_get_peers(r, *_):
        return r

    # Start seeder
    torrent_seeder = loop.run_until_complete(Torrent.create(torrent_file, seeder_dir))
    # Override get_peers method to return an empty list
    trackers = []
    for tracker in torrent_seeder.trackers:
        tracker.get_peers = functools.partial(mock_get_peers, [])
        trackers.append(tracker)
    torrent_seeder.trackers = trackers

    # Start leecher
    torrent_leecher = loop.run_until_complete(Torrent.create(torrent_file, leecher_dir))
    # Override get_peers method to return the address of the seeder
    trackers = []
    for tracker in torrent_leecher.trackers:
        tracker.get_peers = functools.partial(mock_get_peers, [("127.0.0.1", seeder_port)])
        trackers.append(tracker)
    torrent_leecher.trackers = trackers

    async def wait_for(torrent: Torrent, events: List[str]):
        event = None
        while event not in events:
            event = await torrent.queue.get()
        return event

    # Futures
    f_seeder = asyncio.ensure_future(torrent_seeder.download(seeder_port))
    f_wait_accept_conns = asyncio.ensure_future(
        wait_for(torrent_seeder, ["EVENT_ACCEPT_CONNECTIONS", "EVENT_END"])
    )
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
                    f_leecher = asyncio.ensure_future(torrent_leecher.download(leecher_port),
                                                      loop=loop)
                    f_download_complete = asyncio.ensure_future(
                        wait_for(torrent_leecher, ["EVENT_DOWNLOAD_COMPLETE", "EVENT_END"])
                    )
                    futures = futures | {f_leecher, f_download_complete}
                elif result == "EVENT_END":
                    print("leecher failed")

            # Once the leecher has downloaded the file, stop all torrents
            if item == f_download_complete:
                if result == "EVENT_DOWNLOAD_COMPLETE":
                    loop.run_until_complete(torrent_leecher.stop())
                    loop.run_until_complete(torrent_seeder.stop())
                elif result == "EVENT_END":
                    print("seeder failed")

    loop.stop()
    loop.close()

    assert filecmp.dircmp(seeder_dir, data_dir)
    assert filecmp.dircmp(leecher_dir, data_dir)
    shutil.rmtree(tmp_dir)


class EndToEnd(unittest.TestCase):
    def test_seeder_leecher(self):
        """Test data exchanges for a swarm of two peers (seeder and leecher)"""
        logging.basicConfig(
            level=logging.DEBUG,
            format="[%(asctime)s] %(levelname)s [%(name)s.%(funcName)s:%(lineno)d] %(message)s",
            datefmt="%H:%M:%S")

        test_cases_dir = os.path.join(DATA_DIR, "files")
        for d in os.listdir(test_cases_dir):
            if os.path.isdir(os.path.join(test_cases_dir, d)):
                full_directory_path = os.path.join(test_cases_dir, d)
                with self.subTest(directory=full_directory_path):
                    two_peer_swarm(full_directory_path)

