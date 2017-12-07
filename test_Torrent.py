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

from Torrent import Torrent, next_request, init, download
from Peer import Peer


class TestTorrentFunctions(TestCase):
    def test_next_request(self):
        now = datetime.datetime.now()
        with self.subTest(case="Piece pending: request the missing block"):
            piece_index, block_offset = next_request(torrent_pending={0: {0: ({now}, b""),
                                                                          1: (set(), b"")}
                                                                      },
                                                     torrent_pieces=set(),
                                                     peer_pieces={0},
                                                     peer_pending=set(),
                                                     rarity=[(0, 1)],
                                                     endgame=True)
            self.assertEqual((piece_index, block_offset), (0, 1))

        with self.subTest(case="No pending piece: request the rarest piece"):
            piece_index, block_offset = next_request(torrent_pending={},
                                                     torrent_pieces=set(),
                                                     peer_pieces={0, 1},
                                                     peer_pending=set(),
                                                     rarity=[(1, 1), (0, 2)],
                                                     endgame=True)
            self.assertEqual((piece_index, block_offset), (1, 0))

        with self.subTest(case="All pieces requested or downloaded: add a request for a piece"):
            piece_index, block_offset = next_request(torrent_pending={1: {0: ({now}, b"")},
                                                                      2: {0: ({now}, b"")},
                                                                      3: {0: ({now}, b"")}},
                                                     torrent_pieces=set(),
                                                     peer_pieces={1, 2, 3},
                                                     peer_pending={(1, 0), (2, 0)},
                                                     rarity=[(1, 1), (2, 1), (3, 2)],
                                                     endgame=True)
            # The piece re-requested must not be in peer_pending so it has to be piece #3
            self.assertEqual((piece_index, block_offset), (3, 0))

        with self.subTest(case="Peer has no pieces: fail"):
            with self.assertRaises(IndexError):
                next_request(torrent_pending={},
                             torrent_pieces=set(),
                             peer_pieces=set(),
                             peer_pending=set(),
                             rarity=[],
                             endgame=True)

        with self.subTest(case="Peer has no interesting piece: fail"):
            with self.assertRaises(IndexError):
                next_request(torrent_pending={},
                             torrent_pieces={1, 3, 5},
                             peer_pieces={1, 3, 5},
                             peer_pending=set(),
                             rarity=[(1, 1), (3, 1), (5, 1)],
                             endgame=True)

        with self.subTest(case="Interesting pieces already requested to the peer: fail"):
            with self.assertRaises(IndexError):
                next_request(torrent_pending={1: {0: ({now}, b"")},
                                              2: {0: ({now}, b"")},
                                              3: {0: ({now}, b"")}},
                             torrent_pieces=set(),
                             peer_pieces={1, 2, 3},
                             peer_pending={(1, 0), (2, 0), (3, 0)},
                             rarity=[(1, 1), (2, 1), (3, 1)],
                             endgame=True)

        with self.subTest(case="Interesting pieces already requested to another peer: fail"):
            with self.assertRaises(IndexError):
                next_request(torrent_pending={5: {0: ({now}, b"")}},
                             torrent_pieces={0, 1, 2, 3, 4},
                             peer_pieces={5},
                             peer_pending=set(),
                             rarity=[(1, 1), (2, 1), (3, 1), (4, 1), (5, 2)],
                             endgame=False)

        with self.subTest(case="Request all blocks of a file"):
            piece_length = 5
            length = 25
            t = Torrent("", "", b"", [], piece_length, length)
            p = Peer()
            p.pieces = set(range(0, length, piece_length))
            t.piece_rarity = [(piece, 1) for piece in p.pieces]
            t.piece_rarity_sorted = sorted(t.piece_rarity)
            p.chokes_me = False
            t.add_peer(p)

            result = set()
            requests = t.build_requests(p, 1)
            while requests:
                for request in requests:
                    result.add((request.piece_index, request.block_offset))
                requests = t.build_requests(p, 1)

            self.assertEqual(result, set([(p, b) for p in p.pieces for b in range(0, piece_length)]))


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
        loop.set_debug(True)
        executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        loop.set_default_executor(executor)

        dir1 = mkdtemp()
        dir2 = mkdtemp()

        async def hypervisor(loop):
            # Setup a directory and files for the seeder
            copy("./data/files/lorem.txt", dir1)
            with unittest.mock.patch.object(Torrent, 'get_peers') as get_peers_mocked:
                # Mock Torrent.get_peers to return an empty list
                get_peers_mocked.return_value = []
                t1 = init("./data/torrent files/lorem.txt.torrent", dir1)
                # Start the seeder
                f1 = asyncio.ensure_future(download(loop, t1, 6881))

                # Wait until the seeder is ready to accept incoming connections
                item = ""
                while item != "EVENT_ACCEPT_CONNECTIONS":
                    item = await t1.queue.get()

                # Mock Torrent.get_peers to return the address of the seeder
                get_peers_mocked.return_value = [("127.0.0.1", 6881)]
                # Setup a directory and files for the leecher
                t2 = init("./data/torrent files/lorem.txt.torrent", dir2)

                # Start the leecher
                f2 = asyncio.ensure_future(download(loop, t2, 6882), loop=loop)

                # Wait for the download to complete
                item = ""
                while item != "EVENT_DOWNLOAD_COMPLETE":
                    item = await t2.queue.get()

                t2.stop()
                t1.stop()

                await asyncio.gather(*[f1, f2])

        loop.run_until_complete(asyncio.ensure_future(hypervisor(loop), loop=loop))

        print('stopping loop')
        loop.stop()
        loop.close()

        f1 = os.path.join(dir1, "lorem.txt")
        f2 = os.path.join(dir2, "lorem.txt")
        
        self.assertEqual(filecmp.cmp(f1, f2, False), True)
        rmtree(dir1)
        rmtree(dir2)


if __name__ == '__main__':
        unittest.main()
