import concurrent.futures
import filecmp
import unittest.mock
from shutil import copy, rmtree
from tempfile import mkdtemp
from unittest import TestCase

from Peer import Peer
from Torrent import *


class TestTorrentMethods(TestCase):
    def test_request_new_block(self, block_length: int=16384, piece_length: int=16384*3+1):
        q, r = divmod(piece_length, block_length)
        blocks_per_piece = q + int(bool(r))
        torrent_length = 8 * 10 * piece_length

        with self.subTest(case="Peer has no pieces"):
            t = Torrent("", "", b"", [], piece_length, torrent_length)
            p = Peer()
            t.add_peer(p)
            with self.assertRaises(IndexError):
                t.next_request(p.pending, p.pieces)

        with self.subTest(case="Peer has no interesting pieces"):
            t = Torrent("", "", b"", [], piece_length, torrent_length)
            t.pieces = set(range(0, t.nbr_pieces, 2))
            p = Peer()
            t.add_peer(p)
            with self.assertRaises(IndexError):
                t.next_request(p.pending, p.pieces)

        with self.subTest(case="Peer has all the pieces"):
            """Check that the function requests all the necessary blocks."""
            t = Torrent("", "", b"", [], piece_length, torrent_length)
            p = Peer()
            p.pieces = set(range(0, t.nbr_pieces))
            t.add_peer(p)
            p.chokes_me = False
            missing_blocks = set().union(*[
                [(i, b * block_length) for i in range(0, t.nbr_pieces)]
                for b in range(0, blocks_per_piece)
            ])
            p.pending_target = len(missing_blocks)
            MAX_PENDING_REQUESTS = len(missing_blocks)

            while p.pending != missing_blocks:
                reqs = t.build_requests(p)
                if not reqs:
                    break
                for req in reqs:
                    p.pending.add((req.piece_index, req.block_offset))

            self.assertEqual(p.pending, missing_blocks)

        with self.subTest(case="Peer has all the missing pieces"):
            t = Torrent("", "", b"", [], piece_length, torrent_length)
            # We have pieces 0, 2, 4, 6...
            t.pieces = set(range(0, t.nbr_pieces, 2))
            # The peer has pieces 1, 3, 5, 7...
            p = Peer()
            p.pieces = set(range(1, t.nbr_pieces, 2))
            p.pending = set()
            p.chokes_me = False

            t.add_peer(p)
            missing_blocks = set().union(*[
                [(i, b * block_length) for i in range(1, t.nbr_pieces, 2)]
                for b in range(0, blocks_per_piece)
            ])
            p.pending_target = len(missing_blocks)
            MAX_PENDING_REQUESTS = len(missing_blocks)

            while p.pending != missing_blocks:
                reqs = t.build_requests(p)
                if not reqs:
                    break
                for req in reqs:
                    p.pending.add((req.piece_index, req.block_offset))

            self.assertEqual(p.pending, missing_blocks)


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
