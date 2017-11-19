import unittest.mock
import asyncio
import logging
import concurrent.futures

from shutil import copy, rmtree
from tempfile import mkdtemp
from unittest import TestCase

from Torrent import *


class TestTorrentMethods(TestCase):
    def test_request_new_block(self, block_length: int=16384, piece_length: int=16384*3+1):
        q, r = divmod(piece_length, block_length)
        blocks_per_piece = q + int(bool(r))
        torrent_length = 8 * 10 * piece_length

        with self.subTest(case="Peer has no pieces"):
            t = Torrent("", "", b"", [], piece_length, torrent_length)
            peer_pieces = set([])
            self.assertEqual(t.request_new_block(peer_pieces), None)

        with self.subTest(case="Peer has no interesting pieces"):
            t = Torrent("", "", b"", [], piece_length, torrent_length)
            t.pieces = set(range(0, t.nbr_pieces, 2))
            peer_pieces = t.pieces
            self.assertEqual(t.request_new_block(peer_pieces), None)

        with self.subTest(case="Peer has all the pieces"):
            t = Torrent("", "", b"", [], piece_length, torrent_length)
            peer_pieces = set(range(0, t.nbr_pieces))
            requested_blocks = set([])
            req = t.request_new_block(peer_pieces, block_length)
            while req is not None:
                # Record all the block requested
                requested_blocks.add((req.piece_index, req.block_offset))
                req = t.request_new_block(peer_pieces, block_length)
            missing_blocks = set().union(*[
                [(i, b * block_length) for i in range(0, t.nbr_pieces)]
                for b in range(0, blocks_per_piece)
            ])
            self.assertEqual(requested_blocks, missing_blocks)

        with self.subTest(case="Peer has all the missing pieces"):
            t = Torrent("", "", b"", [], piece_length, torrent_length)
            # We have pieces 0, 2, 4, 6...
            t.pieces = set(range(0, t.nbr_pieces, 2))
            # The peer has pieces 1, 3, 5, 7...
            peer_pieces = set(range(1, t.nbr_pieces, 2))
            requested_blocks = set([])
            req = t.request_new_block(peer_pieces)
            while req is not None:
                requested_blocks.add((req.piece_index, req.block_offset))
                req = t.request_new_block(peer_pieces)
            missing_blocks = set().union(*[
                [(i, b * block_length) for i in range(1, t.nbr_pieces, 2)]
                for b in range(0, blocks_per_piece)
            ])
            self.assertEqual(requested_blocks, missing_blocks)


@unittest.skip("For now this test never ends")
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
            c1 = download(loop, "./data/torrent files/lorem.txt.torrent", 6881, dir1)

        # Second instance of PyTo (leecher)
        dir2 = mkdtemp()
        with unittest.mock.patch.object(Torrent, 'get_peers') as get_peers_mocked:
            get_peers_mocked.return_value = [("127.0.0.1", 6881)]
            c2 = download(loop, "./data/torrent files/lorem.txt.torrent", 6882, dir2)

        loop.run_until_complete(asyncio.gather(*(c1 + c2)))

        loop.close()
        rmtree(dir1)
        rmtree(dir2)
