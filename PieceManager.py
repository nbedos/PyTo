from collections import OrderedDict
from random import SystemRandom
from typing import Dict, Set, Tuple, List


RARITY_PERCENT = 20
ENDGAME_PERCENT = 90
MAX_PENDING_REQUESTS = 4
assert (0 <= RARITY_PERCENT <= 100)
assert (0 <= ENDGAME_PERCENT <= 100)
assert (MAX_PENDING_REQUESTS > 0)


class PieceManager:
    """Store information about pieces and blocks:
        - pieces owned
        - incomplete pieces
        - blocks requested but not received yet
        - piece availability in the swarm

        Find the most interesting block to request"""
    def __init__(self, file_length: int, piece_length: int, block_length: int=16384):
        if not (0 < block_length <= piece_length <= file_length):
            raise ValueError("Lengths must verify "
                             "0 < block_length <= piece_length <= file_length")
        # ** FILE ATTRIBUTES **
        # Length of the whole file
        self.file_length = file_length
        # Length of a piece (the last piece of a file may be shorter)
        self.default_piece_length = piece_length
        # Total number of pieces
        q, r = divmod(self.file_length, self.default_piece_length)
        self.nbr_pieces = q + int(bool(r))
        self.endgame_threshold = self.nbr_pieces * ENDGAME_PERCENT // 100
        # Length of a regular block (the last block of a piece may be shorter)
        self._block_length = block_length

        # ** PIECES AND BLOCKS BOOKKEEPING **
        # Pieces owned
        self.pieces: Set[int] = set()
        # Pieces ready to be written on disk
        self.pieces_to_write: Dict[int, bytes] = {}
        # Blocks that have been downloaded but don't form a full piece yet
        self.blocks_downloaded: Dict[int, Dict[int, bytes]] = {}
        # Blocks which have or will soon be requested
        self.requests: Dict[Tuple[int, int], Set[int]] = {}
        # Available pieces in the swarm and its count
        self._availability: Dict[int, int] = OrderedDict([])
        self._availability_is_sorted = False
        # All pieces the torrent is missing
        self.missing_pieces = set(range(self.nbr_pieces))

    @property
    def availability(self):
        """If needed, sort the pieces by increasing rarity before returning _availability"""
        if not self._availability_is_sorted:
            self._availability = OrderedDict(sorted(self._availability.items(), key=lambda x: x[1]))
            self._availability_is_sorted = True
        return self._availability

    def register_block_requested(self, piece_index: int, block_offset: int, peer_id: int):
        """Take note that the block has been requested"""
        if (piece_index, block_offset) not in self.requests:
            self.missing_pieces.remove(piece_index)
            block_length = self.block_length(piece_index, block_offset)
            for offset in range(0, self.piece_length(piece_index), block_length):
                self.requests[(piece_index, offset)] = set()
        self.requests[(piece_index, block_offset)].add(peer_id)

    # TODO: Check the block_length ?
    def register_block_received(self,
                                piece_index: int,
                                block_offset: int,
                                block: bytes,
                                peer_id: int):
        """Take note that the block has been received from the peer

        Raise ValueError if the block was not requested to this particular peer"""
        try:
            self.requests[(piece_index, block_offset)].remove(peer_id)
        except KeyError:
            raise ValueError("No matching request found")
        if not self.requests[(piece_index, block_offset)]:
            del self.requests[(piece_index, block_offset)]

        if piece_index not in self.blocks_downloaded:
            self.blocks_downloaded[piece_index] = {}

        if block_offset not in self.blocks_downloaded[piece_index]:
            self.blocks_downloaded[piece_index][block_offset] = {}

        self.blocks_downloaded[piece_index][block_offset] = block

        if len(self.blocks_downloaded[piece_index]) == self.nbr_blocks(piece_index):
            blocks_of_piece = sorted(self.blocks_downloaded[piece_index].items())
            piece = b"".join([block for _, block in blocks_of_piece])
            self.pieces_to_write[piece_index] = piece
            self.pieces.add(piece_index)
            del self.blocks_downloaded[piece_index]

    def register_piece_owned(self, piece_index: int):
        """Take note that we own this piece"""
        self.pieces.add(piece_index)

    def register_peer_has(self, piece_index: int):
        """Take note that a peer owns this piece"""
        try:
            self._availability[piece_index] += 1
        except KeyError:
            self._availability[piece_index] = 1

        self._availability_is_sorted = False

    def remove_peer(self, peer_id: int, peer_pieces: Set[int]):
        """Take note that this peer was disconnected"""
        for piece_index in peer_pieces:
            self._availability[piece_index] -= 1
        if peer_pieces:
            self._availability_is_sorted = False

        for block in self.requests:
            try:
                self.requests[block].remove(peer_id)
            except KeyError:
                pass

    def next_block(self,
                   peer_pieces: Set[int],
                   peer_id: int) -> Tuple[int, int]:
        """Return the most interesting block to download as a tuple (piece_index, block_offset)

        IndexError is raised if no block is eligible for download"""
        candidates: Set[Tuple[int, int]] = set()

        # Choice #1: Choose a block which has not been requested yet and which belongs to a piece
        # owned by the peer
        for (piece_index, block_offset), peers in self.requests.items():
            if (piece_index in peer_pieces) and (not peers):
                candidates.add((piece_index, block_offset))
                break

        # Choice #2: Pick the first block of one of the rarest pieces
        if not candidates:
            interesting_pieces = self.missing_pieces & peer_pieces
            peer_rarity = [(p, r) for p, r in self.availability.items() if p in interesting_pieces]
            # Keep RARITY_PERCENT of the rarest pieces
            nbr_rare_pieces = max(1, len(peer_rarity) * RARITY_PERCENT // 100)
            candidates = set((piece, 0) for piece, _ in peer_rarity[:nbr_rare_pieces])

        # Choice #3: Endgame mode. Pick a block of an incomplete piece which has already been
        # requested but never received, unless there are already MAX_PENDING_REQUESTS requests
        # for that block.
        if not candidates and self.endgame():
            for (piece, block_offset), peers in self.requests.items():
                if piece in peer_pieces and (piece not in self.blocks_downloaded or
                                             block_offset not in self.blocks_downloaded[piece]):
                    if (peer_id not in peers) and (len(peers) < MAX_PENDING_REQUESTS):
                        candidates.add((piece, block_offset))
                        break

        if not candidates:
            raise IndexError("No block eligible for request")

        return SystemRandom().choice(list(candidates))

    def piece_length(self, piece_index: int) -> int:
        """Return the length of the piece"""
        if not (0 <= piece_index < self.nbr_pieces):
            raise ValueError("Invalid piece_index")

        piece_offset = piece_index * self.default_piece_length
        return min(self.default_piece_length, self.file_length - piece_offset)

    def block_length(self, piece_index: int, block_offset: int) -> int:
        """Return the length of the block"""
        return min(self._block_length, self.piece_length(piece_index) - block_offset)

    def nbr_blocks(self, piece_index: int) -> int:
        """Return the number of blocks in the piece"""
        q, r = divmod(self.piece_length(piece_index), self._block_length)
        return q + int(bool(r))

    def endgame(self) -> bool:
        """Endgame starts when we have more than endgame_threshold pieces"""
        return len(self.pieces) >= self.endgame_threshold
