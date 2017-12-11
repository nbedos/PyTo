"""
Torrent module

An instance of the Torrent class represents a Torrent file
"""
import asyncio
import datetime
import logging
import os
import socket
import urllib.parse
import urllib.request
from hashlib import sha1
from random import SystemRandom
from struct import unpack, iter_unpack, error as struct_error
from typing import Iterator, Tuple, Union, List, Set, Dict

from BEncoding import bdecode, bencode
from Messages import Message, KeepAlive, Choke, Unchoke, Interested, NotInterested, Have, \
                     BitField, Request, Piece, Cancel, Port, HandShake
from Peer import Peer, exchange


RARITY_PERCENT: int = 20
ENDGAME_PERCENT: int = 90
MAX_PENDING_REQUESTS: int = 4
REQUEST_TIMEOUT: int = 10

module_logger = logging.getLogger(__name__)


class TorrentAdapter(logging.LoggerAdapter):
    """Add the name of the Torrent to logger messages"""
    def process(self, msg, kwargs):
        return '{:>20} {}'.format(self.extra['name'], msg), kwargs


class Torrent:
    """Represent a Torrent file

    Attributes:
        - announce: announce URL of the tracker
        - name: suggested filename for the downloaded file
        - info_hash: SHA1 hash of the info dictionary in the torrent file
        - hashes: SHA1 hash of each piece of the torrent
        - piece_length: length in bytes of a piece
        - length: length in bytes of the file
    """
    def __init__(self, announce: str, name: str, info_hash: bytes, hashes: List[bytes],
                 piece_length: int, length: int):
        self.announce = announce
        self.name = _sanitize(name)
        self.info_hash = info_hash
        self.hashes = hashes
        if not (0 < piece_length <= length):
            raise ValueError("Lengths must verify 0 < piece_length <= length")
        self.length = length
        self.piece_length = piece_length
        q, r = divmod(self.length, self.piece_length)
        self.nbr_pieces = q + int(bool(r))
        self.pieces = set([])
        self.file = None
        self.pieces_to_write = dict([])

        self.peers = dict([])
        self.blacklist = dict([])
        self.pending = dict([])
        # TODO: remove pieces from rarity data structures when a peer is disconnected
        self.piece_rarity = dict([])
        self.piece_rarity_sorted = []

        self.logger = TorrentAdapter(module_logger, {'name': self.name})

        self.futures = set([])
        self.socket = None

        self.queue = asyncio.Queue(50)

    @classmethod
    def from_file(cls, torrent_file: str):
        with open(torrent_file, "rb") as f:
            m = bdecode(f.read())
        try:
            info = m[b'info']
            return cls(m[b'announce'].decode("utf-8"),
                       info[b'name'].decode("utf-8"),
                       sha1(bencode(info)).digest(),
                       _split(info[b"pieces"], 20),
                       info[b"piece length"],
                       info[b"length"])
        except KeyError:
            pass
        raise ValueError("Invalid torrent file")

    def __repr__(self) -> str:
        return "\n\t".join([
             "Torrent: {}".format(self.name),
             "    info_hash: {}".format(self.info_hash),
             "     announce: {}".format(self.announce),
             "       length: {}".format(self.length),
             " piece_length: {}".format(self.piece_length),
             "   nbr_pieces: {}".format(self.nbr_pieces),
             "       pieces: {}".format(self.pieces),
        ])

    def read_piece(self, piece_index: int) -> bytes:
        self.logger.debug("reading piece #{}".format(piece_index))
        offset = piece_index * self.piece_length
        self.file.seek(offset)
        return self.file.read(self.piece_length)

    def _seek_and_write(self, piece_index: int, piece: bytes):
        self.file.seek(piece_index * self.piece_length)
        self.file.write(piece)

    async def write_piece(self, loop):
        my_pieces_to_write = self.pieces_to_write.copy()
        self.pieces_to_write = dict([])
        for piece_index, piece in my_pieces_to_write.items():
            self.logger.debug("writing piece #{}".format(piece_index))
            await asyncio.wait([
                loop.run_in_executor(None, self._seek_and_write, piece_index, piece)
            ])

    def init_files(self, download_dir: str):
        """Create missing files, check existing ones"""
        os.makedirs(download_dir, exist_ok=True)
        torrent_file = os.path.join(download_dir, str(self.name))
        reopen_read_write = False
        try:
            f = open(torrent_file, "rb")
            if os.stat(torrent_file).st_size != self.length:
                print(os.stat(torrent_file).st_size, self.length)

                raise ValueError("The file size does not match with the torrent size")
            pieces = iter(lambda: f.read(self.piece_length), b"")
            for piece_index, piece in enumerate(pieces):
                if self.hashes[piece_index] == sha1(piece).digest():
                    self.pieces.add(piece_index)
                else:
                    reopen_read_write = True
        except FileNotFoundError:
            f = open(torrent_file, "wb")
            f.truncate(self.length)
            reopen_read_write = True

        if reopen_read_write:
            f.close()
            f = open(torrent_file, "rb+")

        self.file = f

    def get_peers(self) -> Iterator[Tuple[str, int]]:
        """Send an announce query to the tracker"""
        h = {
            'info_hash': self.info_hash,
            'peer_id': "-HT00000000000000000",
            'port': 6881,
            'uploaded': 0,
            'downloaded': 0,
            'left': self.length,
            'event': "started",
            'compact': 1
        }

        url = "{}?{}".format(self.announce, urllib.parse.urlencode(h))
        self.logger.debug("announce = {}".format(url))
        with urllib.request.urlopen(url) as response:
            d = bdecode(response.read())
            return map(_decode_ipv4, _split(d[b"peers"], 6))

    def add_peer(self, p):
        if (p.ip, p.port) in self.blacklist:
            raise ValueError("This peer is blacklisted")

        # TODO: Is there a way to get an exception when inserting the key if it is already in the
        # dictionary ?
        if (p.ip, p.port) not in self.peers:
            self.peers[(p.ip, p.port)] = p

    # TODO: implement remove_peer
    def remove_peer(self, p):
        pass

    def is_complete(self):
        self.logger.debug("missing pieces: {}".format(set(range(0, self.nbr_pieces)) - self.pieces))
        return self.pieces == set(range(0, self.nbr_pieces))

    def build_answer_to(self, message: Message, initiated: bool) -> List[Message]:
        handler_name = '_build_answer_to_' + message.__class__.__name__
        try:
            handler = getattr(self, handler_name)
        except AttributeError:
            self.logger.error("No handler found for message: {}".format(message))
            raise NotImplemented
        return handler(message, initiated)

    def _build_answer_to_HandShake(self, message: HandShake, initiated) -> List[Message]:
        if initiated:
            return []
        else:
            return [
                HandShake(self.info_hash),
                BitField(self.pieces, self.nbr_pieces)
            ]

    def _build_answer_to_Choke(self, message: Choke, _) -> List[Message]:
        return []

    def _build_answer_to_Unchoke(self, message: Unchoke, _) -> List[Message]:
        return []

    def _build_answer_to_Interested(self, message: Interested, _) -> List[Message]:
        # TODO: update peer status
        return [Unchoke()]

    def _build_answer_to_NotInterested(self, message: NotInterested, _) -> List[Message]:
        # TODO: update peer status
        return [Choke()]

    def _build_answer_to_Have(self, message: Have, _) -> List[Message]:
        return []

    def _build_answer_to_BitField(self, message: BitField, _) -> List[Message]:
        # Check if the peer has any interesting piece
        requestable_pieces = (self.pieces ^ message.pieces) & message.pieces
        if requestable_pieces:
            return [Interested()]
        else:
            return []

    def _build_answer_to_Request(self, message: Request, _) -> List[Message]:
        block = b""
        return [
            Piece(16384,
                  message.piece_index,
                  message.block_offset,
                  block)
        ]

    def _build_answer_to_Piece(self, message: Piece, _) -> List[Message]:
        if message.piece_index in self.pieces_to_write:
            return [Have(message.piece_index)]
        else:
            return []

    def _build_answer_to_Port(self, message: Port, _) -> List[Message]:
        return []

    def _build_answer_to_Cancel(self, message: Cancel, _) -> List[Message]:
        return []

    def _build_answer_to_KeepAlive(self, message: KeepAlive, _) -> List[Message]:
        return []

    def update_from_message(self, message: Message):
        handler_name = '_update_from_' + message.__class__.__name__
        try:
            handler = getattr(self, handler_name)
        except AttributeError:
            self.logger.error("No handler found for message: {}".format(message))
            raise NotImplemented
        handler(message)

    def _update_from_HandShake(self, message: HandShake):
        if self.info_hash != message.info_hash:
            raise ValueError("Invalid HandShake message")

    def _update_from_Choke(self, message: Choke):
        pass

    def _update_from_Unchoke(self, message: Unchoke):
        pass

    def _update_from_Interested(self, message: Interested):
        pass

    def _update_from_NotInterested(self, message: NotInterested):
        pass

    def _update_from_Have(self, message: Have):
        try:
            self.piece_rarity[message.piece_index] += 1
        except KeyError:
            self.piece_rarity[message.piece_index] = 1
        self.piece_rarity_sorted = sorted(self.piece_rarity.items(), key=lambda x: x[1])

    def _update_from_BitField(self, message: BitField):
        # Update rarity
        for piece in message.pieces:
            try:
                self.piece_rarity[piece] += 1
            except KeyError:
                self.piece_rarity[piece] = 1
        self.piece_rarity_sorted = sorted(self.piece_rarity.items(), key=lambda x: x[1])

    def _update_from_Request(self, message: Request):
        pass

    def _update_from_Piece(self, message: Piece):
        try:
            blocks = self.pending[message.piece_index]
            requests, block = blocks[message.block_offset]
            if (not requests) or block:
                raise KeyError
        except KeyError:
            self.logger.debug("block already downloaded (piece #{}, offset {})".format(
                message.piece_index, message.block_offset))
            return

        blocks[message.block_offset] = (requests, message.block)
        # Check if we've got all the blocks for this piece
        if all([block for _, block in blocks.values()]):
            piece = b"".join([block for _, block in blocks.values()])
            if self.hashes[message.piece_index] != sha1(piece).digest():
                self.logger.error("Hashing failed for piece #{}".format(
                    message.piece_index))
                raise ValueError("Invalid piece")

            self.logger.debug("Hashing succeeded for piece #{}".format(message.piece_index))
            self.pieces_to_write[message.piece_index] = piece
            self.pieces.add(message.piece_index)
            self.logger.debug("Updated list of pieces: {}".format(self.pieces))
            del self.pending[message.piece_index]

            if self.is_complete():
                # TODO: reopen files in read-only mode
                self.logger.debug("Download complete. Nothing more to request")
                try:
                    self.queue.put_nowait("EVENT_DOWNLOAD_COMPLETE")
                except asyncio.QueueFull:
                    self.logger.warning("Queue full, could not write event")

    def _update_from_Port(self, message: Port):
        pass

    def _update_from_Cancel(self, message: Cancel):
        pass

    def _update_from_KeepAlive(self, message: KeepAlive):
        pass

    async def complement(self, message: Piece) -> Piece:
        loop = asyncio.get_event_loop()
        done, not_done = await asyncio.wait([loop.run_in_executor(None,
                                                                  self.read_piece,
                                                                  message.piece_index)])
        results = [task.result() for task in done]
        piece = results.pop()
        block = piece[message.block_offset:message.block_offset+message.block_length]
        return Piece(len(block),
                     message.piece_index,
                     message.block_offset,
                     block)

    def build_requests(self, peer: Peer, block_length: int=16384):
        """Build a list of request to be sent to the peer

        Side effect: update the list of pending piece of the Torrent instance"""
        if peer.chokes_me:
            return []

        l = []
        assert(0 <= ENDGAME_PERCENT <= 100)
        endgame_threshold = self.nbr_pieces * ENDGAME_PERCENT // 100
        endgame = len(self.pieces) >= endgame_threshold
        for _ in range(len(peer.pending), peer.pending_target, 1):
            try:
                piece_index, block_offset = next_request(self.pending,
                                                         self.pieces,
                                                         peer.pieces,
                                                         peer.pending,
                                                         self.piece_rarity_sorted,
                                                         endgame)
            except IndexError:
                break

            # Compute the length of the piece since the last one may be shorter
            if piece_index == self.nbr_pieces - 1:
                piece_length = self.length - self.piece_length * (self.nbr_pieces - 1)
            else:
                piece_length = self.piece_length

            # Update the list of pending pieces of the Torrent instance
            if piece_index not in self.pending:
                q, r = divmod(piece_length, block_length)
                nbr_blocks = q + int(bool(r))
                self.pending[piece_index] = {
                    (i * block_length): (set(), b"") for i in range(0, nbr_blocks)
                }
            requests, _ = self.pending[piece_index][block_offset]
            requests.add(datetime.datetime.now())

            l.append(Request(piece_index, block_offset, block_length))
        return l

    def stop(self):
        for f in self.futures:
            f.cancel()
        print(self.futures)

    #TODO: Why does test_Torrent fails if we close all sockets ?
    # "OSError: [WinError 10038] Une opération a été tentée sur autre chose qu’un socket"
    def close(self):
        self.queue.put_nowait("EVENT_END")
        self.logger.info("EVENT_END")
        # if self.socket:
        #     print(self.socket)
        #     #self.socket.shutdown(socket.SHUT_RDWR)
        #     self.socket.close()
        # for peer in self.peers.values():
        #     print(peer.socket)
        #     if peer.socket:
        #         peer.socket.shutdown(socket.SHUT_RDWR)
        #         peer.socket.close()
        self.file.close()

    def start_server(self, port: int):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setblocking(0)
        self.socket.bind(('', port))
        self.socket.listen(5)


def init(torrent_file: str, download_dir: str):
    torrent = Torrent.from_file(torrent_file)
    torrent.init_files(download_dir)
    logging.debug(torrent)
    return torrent


async def download(loop: asyncio.AbstractEventLoop, torrent: Torrent, listen_port: int):

    # Connect to peers
    for ip, port in torrent.get_peers():
        f = asyncio.ensure_future(exchange(torrent, ip=ip, port=port, initiated=True))
        torrent.futures.add(f)

    # Start accepting new connections
    torrent.start_server(listen_port)
    print("server:", torrent.socket)
    f_accept = asyncio.ensure_future(loop.sock_accept(torrent.socket))
    torrent.futures.add(f_accept)
    try:
        torrent.queue.put_nowait("EVENT_ACCEPT_CONNECTIONS")
        torrent.logger.info("EVENT_ACCEPT_CONNECTIONS")
    except asyncio.QueueFull:
        torrent.logger.warning("Queue full, could not write event")

    while torrent.futures:
        try:
            done, torrent.futures = await asyncio.wait(torrent.futures,
                                                       return_when=asyncio.FIRST_COMPLETED)
        except asyncio.CancelledError:
            break

        for item in done:
            try:
                result = item.result()
            except asyncio.CancelledError:
                torrent.logger.info("Task cancelled: {}".format(item))
            # We catch ALL exceptions here, otherwise one of our futures may fail silently
            except Exception:
                torrent.logger.exception("Future failed")
                torrent.stop()
                raise
            else:
                if item == f_accept:
                    # Start exchanging data with the peer
                    peer_socket, (ip, port) = result
                    f = asyncio.ensure_future(exchange(torrent, ip, port, peer_socket, initiated=False))
                    torrent.futures.add(f)
                    # Set up another future to accept incoming connections
                    f_accept = asyncio.ensure_future(loop.sock_accept(torrent.socket))
                    torrent.futures.add(f_accept)

    print(torrent.futures)
    torrent.close()


def next_request(torrent_pending: Dict[int, Dict[int, Tuple[Set[datetime.datetime], bytes]]],
                 torrent_pieces:  Set[int],
                 peer_pieces:     Set[int],
                 peer_pending:    Set[Tuple[int, int]],
                 rarity:          List[Tuple[int, int]],
                 endgame:         bool) -> Tuple[int, int]:
    """Choose the next block to download and return the corresponding Request message

    Raise IndexError if no block is eligible for download

    This function uses the following constants:
        - RARITY_PERCENT: When choosing a rare piece, pick at random among the RARITY_PERCENT
        rarest pieces owned by the peer
        - ENDGAME_PERCENT: Enter endgame mode if at least ENDGAME_PERCENT of the pieces have
        been downloaded
        - MAX_PENDING_REQUESTS: Maximum number of pending requests for a single block. Requests
        which have timed out are not taken into account
        - REQUEST_TIMEOUT: Requests lasting longer than REQUEST_TIMEOUT are ignored when
        counting pending requests
    """
    candidates: Set[Tuple[int, int]] = set()
    now = datetime.datetime.now()

    def request_timed_out(t: datetime.datetime):
        return (t - now).total_seconds() > REQUEST_TIMEOUT

    # Choice #1: Pick among the missing blocks of an incomplete piece
    # Requests dating from more than REQUEST_TIMEOUT seconds ago are ignored
    for piece in set(torrent_pending) & peer_pieces:
        for offset, (requests, block) in torrent_pending[piece].items():
            if not block:
                if (not requests) or all(map(request_timed_out, requests)):
                    candidates.add((piece, offset))

    # Choice #2: Pick the first block of one of the rarest pieces
    if not candidates:
        # Exclude pieces which have been downloaded and pieces which have been requested
        interesting_pieces = peer_pieces - torrent_pieces - set(torrent_pending)
        peer_rarity = [(p, r) for p, r in rarity if p in interesting_pieces]
        assert (0 < RARITY_PERCENT <= 100)
        # Keep RARITY_PERCENT of the rarest pieces
        nbr_rare_pieces = max(1, len(peer_rarity) * RARITY_PERCENT // 100)
        candidates = set((piece, 0) for piece, _ in peer_rarity[:nbr_rare_pieces])

    # Choice #3: Endgame mode. Pick a block of an incomplete piece which has already been
    # requested but never received, unless there are already MAX_PENDING_REQUESTS requests
    # for that block.
    if not candidates and endgame:
        for piece in set(torrent_pending) & peer_pieces:
            for offset, (requests, block) in torrent_pending[piece].items():
                if (not block) and (piece, offset) not in peer_pending:
                    pending_requests = [r for r in requests if not request_timed_out(r)]
                    if len(pending_requests) < MAX_PENDING_REQUESTS:
                        candidates.add((piece, offset))

    if not candidates:
        raise IndexError("No block eligible for request")

    piece_index, block_offset = SystemRandom().choice(list(candidates))
    return piece_index, block_offset


def _split(l: list, n: int) -> list:
    """Split the list l in chunks of size n"""
    if n < 0:
        raise ValueError("n must be >= 0")
    i = 0
    chunks = []
    while l[i:i+n]:
        chunks.append(l[i:i+n])
        i = i + n
    return chunks


def _sanitize(filename: str) -> str:
    allowed_characters = {' ', '-', '[', ']', '}', '{', '_', '.'}
    return "".join([c for c in filename if c.isalnum() or c in allowed_characters]).rstrip()


def _decode_ipv4(buffer: bytes) -> (str, int):
    try:
        ip_str, port = unpack(">4sH", buffer)
        ip = ".".join([str(n) for n, in iter_unpack(">B", ip_str)])
        return ip, port
    except struct_error:
        pass
    raise ValueError("Invalid (ip, port)")


if __name__ == '__main__':
    pass
