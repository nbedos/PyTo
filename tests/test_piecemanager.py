import secrets
import unittest
from unittest import TestCase

from pyto.piecemanager import PieceManager


class TestPieceManager(TestCase):
    def test_piece_length(self):
        with self.subTest(case="Last piece length is a multiple of the block length"):
            p = PieceManager(file_length=13, piece_length=4, block_length=1)
            self.assertEqual(p.piece_length(piece_index=3), 1)

        with self.subTest(case="Last piece is shorter than the block length"):
            p = PieceManager(file_length=13, piece_length=4, block_length=2)
            self.assertEqual(p.piece_length(piece_index=3), 1)

        with self.subTest(case="File length is a multiple of the piece length"):
            p = PieceManager(file_length=4, piece_length=2, block_length=2)
            self.assertEqual(p.piece_length(piece_index=1), 2)

    def test_block_length(self):
        with self.subTest(case="First block of a piece"):
            p = PieceManager(file_length=20, piece_length=8, block_length=4)
            self.assertEqual(p.block_length(piece_index=0, block_offset=0), 4)

        with self.subTest(case="Last block identical to other blocks"):
            p = PieceManager(file_length=20, piece_length=8, block_length=4)
            self.assertEqual(p.block_length(piece_index=0, block_offset=4), 4)

        with self.subTest(case="Last block shorter than other blocks"):
            p = PieceManager(file_length=20, piece_length=9, block_length=4)
            self.assertEqual(p.block_length(piece_index=0, block_offset=8), 1)

    def test_register_block_received(self):
        with self.subTest(case="Receive a block that was not requested: fail"):
            p = PieceManager(file_length=10, piece_length=1, block_length=1)
            with self.assertRaises(ValueError):
                p.register_block_received(piece_index=0, block_offset=0, block=b".", peer_id=1)

        with self.subTest(case="Receive a block that was requested to another peer: fail"):
            p = PieceManager(file_length=10, piece_length=1, block_length=1)
            p.register_block_requested(piece_index=0, block_offset=0, peer_id=1)
            with self.assertRaises(ValueError):
                p.register_block_received(piece_index=0, block_offset=0, block=b".", peer_id=2)

    def test_remove_peer(self):
        with self.subTest(case="After removal of a peer, operations on its old requests must fail"):
            p = PieceManager(file_length=10, piece_length=5, block_length=1)
            # Peer #0 has both pieces
            p.register_peer_has(0)
            p.register_peer_has(1)
            # Peer #1 has both pieces
            p.register_peer_has(0)
            p.register_peer_has(1)
            p.register_block_requested(piece_index=0, block_offset=0, peer_id=0)
            p.register_block_requested(piece_index=0, block_offset=1, peer_id=1)

            p.remove_peer(peer_id=0, peer_pieces={0, 1})

            # After removal of the peer the total count of pieces in the swarm drops for 4 to 2
            self.assertEqual(sum(p.availability.values()), 2)

            block = b"." * p.piece_length(0)
            # Registration of a block coming from a removed peer must fail
            with self.assertRaises(ValueError):
                p.register_block_received(piece_index=0, block_offset=0, block=block, peer_id=0)

    def test_availability(self):
        with self.subTest(case="Pieces must be ordered by increasing count (or rarest first)"):
            p = PieceManager(file_length=10, piece_length=1, block_length=1)
            all_pieces = [0, 1, 2, 3, 4, 0, 1, 2, 3, 0, 1, 2, 0, 1, 0]
            for piece in all_pieces:
                p.register_peer_has(piece)
            self.assertEqual(list(p.availability.items()), [(4, 1), (3, 2), (2, 3), (1, 4), (0, 5)])

    def test_next_block(self):
        with self.subTest(case="Request the missing block"):
            p = PieceManager(file_length=4, piece_length=2, block_length=1)
            # Pieces #0 and #1 are available in the swarm
            p.register_peer_has(0)
            p.register_peer_has(1)
            # Request all blocks except (1, 1)
            p.register_block_requested(piece_index=0, block_offset=0, peer_id=0)
            p.register_block_requested(piece_index=0, block_offset=1, peer_id=0)
            p.register_block_requested(piece_index=1, block_offset=0, peer_id=0)
            # All 3 blocks received
            p.register_block_received(piece_index=0, block_offset=0, block=b"a", peer_id=0)
            p.register_block_received(piece_index=0, block_offset=1, block=b"b", peer_id=0)
            p.register_block_received(piece_index=1, block_offset=0, block=b"c", peer_id=0)
            # Request the last one
            piece_index, block_offset = p.next_block(peer_pieces={0, 1},
                                                     peer_id=0)
            self.assertEqual((piece_index, block_offset), (1, 1))

        with self.subTest(case="No pending piece: request the rarest piece"):
            p = PieceManager(file_length=4, piece_length=2, block_length=1)
            # Piece #1 is more rare and should be requested first
            p.register_peer_has(piece_index=0)
            p.register_peer_has(piece_index=0)
            p.register_peer_has(piece_index=1)
            piece_index, _ = p.next_block(peer_pieces={0, 1},
                                          peer_id=0)
            self.assertEqual(piece_index, 1)

        with self.subTest(case="All pieces requested or downloaded: add a request for a piece"):
            p = PieceManager(file_length=4, piece_length=2, block_length=1)
            # Pieces #0 and #1 are available in the swarm
            p.register_peer_has(piece_index=0)
            p.register_peer_has(piece_index=1)
            # Request all blocks to peer #0
            p.register_block_requested(piece_index=0, block_offset=0, peer_id=0)
            p.register_block_requested(piece_index=0, block_offset=1, peer_id=0)
            p.register_block_requested(piece_index=1, block_offset=0, peer_id=0)
            p.register_block_requested(piece_index=1, block_offset=1, peer_id=0)
            # We've received all blocks except (1, 1)
            p.register_block_received(piece_index=0, block_offset=0, block=b".", peer_id=0)
            p.register_block_received(piece_index=0, block_offset=1, block=b".", peer_id=0)
            p.register_block_received(piece_index=1, block_offset=0, block=b".", peer_id=0)
            # Request a block to peer #1
            piece_index, block_offset = p.next_block(peer_pieces={0, 1},
                                                     peer_id=1)
            self.assertEqual((piece_index, block_offset), (1, 1))

        with self.subTest(case="All blocks owned or already requested to the peer: fail"):
            p = PieceManager(file_length=2, piece_length=1, block_length=1)
            # Pieces #0 and #1 are available in the swarm
            p.register_piece_owned(piece_index=0)
            p.register_piece_owned(piece_index=1)
            # Request and receive block (0, 0)
            p.register_block_requested(piece_index=0, block_offset=0, peer_id=0)
            p.register_block_received(piece_index=0, block_offset=0, block=b".", peer_id=0)
            # Block (1, 0) is the only one remaining but it has already been requested
            with self.assertRaises(IndexError):
                p.next_block(peer_pieces={0, 1}, peer_id=0)

        with self.subTest(case="Peer has no interesting piece: fail"):
            p = PieceManager(file_length=4, piece_length=2, block_length=1)
            # Pieces #0 and #1 are available in the swarm
            p.register_peer_has(piece_index=0)
            p.register_peer_has(piece_index=1)
            # Request and received piece #0
            p.register_block_requested(piece_index=0, block_offset=0, peer_id=0)
            p.register_block_received(piece_index=0, block_offset=0, block=b".", peer_id=0)
            p.register_block_requested(piece_index=0, block_offset=1, peer_id=0)
            p.register_block_received(piece_index=0, block_offset=1, block=b".", peer_id=0)
            # This peer only offers piece #0: fail
            with self.assertRaises(IndexError):
                p.next_block(peer_pieces={0},
                             peer_id=0)

        with self.subTest(case="Only one interesting piece available but already requested: "
                               "fail (too early for endgame)"):
            p = PieceManager(file_length=4, piece_length=1, block_length=1)
            # Pieces #0, #1, #2, #3 are available in the swarm
            p.register_peer_has(piece_index=0)
            p.register_peer_has(piece_index=1)
            p.register_peer_has(piece_index=2)
            p.register_peer_has(piece_index=3)
            # Block (0, 0) has already been requested to peer #1
            p.register_block_requested(piece_index=0, block_offset=0, peer_id=1)
            # Peer #0 offers only block (0, 0) which has already been requested.
            # It's too early for endgame mode so we cannot request the block a second time
            with self.assertRaises(IndexError):
                p.next_block(peer_pieces={0},
                             peer_id=0)

        # Test various combinations of length, especially cases where lengths are not multiples of
        # each other to check if a shorter last piece or block is well handled
        cases = [(16384 * 64, 16384 * 4, 16384),
                 (16384 * 64 + 1, 16384 * 4, 16384),
                 (16384 * 64 + 1, 16384 * 4 + 1, 16384),
                 (16384 * 64, 16384 * 4 + 1, 16384),
                 (16384 * 64, 16384 * 4, 16384 + 1)]
        for file_length, piece_length, block_length in cases:
            with self.subTest(case="Request all pieces of a file",
                              file_length=file_length,
                              piece_length=piece_length,
                              block_length=block_length):

                file_content = secrets.token_bytes(file_length)
                p = PieceManager(file_length, piece_length, block_length)
                all_pieces = set(range(p.nbr_pieces))
                for piece in all_pieces:
                    p.register_peer_has(piece)

                while True:
                    try:
                        piece_index, block_offset = p.next_block(peer_pieces=all_pieces,
                                                                 peer_id=0)
                        p.register_block_requested(piece_index, block_offset, peer_id=0)
                        offset = piece_index * piece_length + block_offset
                        block = file_content[offset:offset+p.block_length(piece_index, block_offset)]
                        p.register_block_received(piece_index, block_offset, block, peer_id=0)
                    except IndexError:
                        break

                downloaded_content = b"".join([b for _, b in sorted(p.pieces_to_write.items())])
                # TODO: move some of theses assertions to test_register
                self.assertEqual(p.pieces, all_pieces)
                self.assertEqual(p.missing_pieces, set())
                self.assertEqual(p.requests, {})
                self.assertEqual(p.blocks_downloaded, {})
                self.assertEqual(file_content, downloaded_content)


if __name__ == '__main__':
    unittest.main()
