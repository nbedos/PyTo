"""
Torrent module

An instance of the Torrent class represents a Torrent file
"""
import asyncio
import logging
import os
import urllib.parse
import urllib.request
from hashlib import sha1
from struct import unpack, iter_unpack, error as struct_error
from typing import Iterator, Tuple, Union, List, Set, Dict

from pyto.bencoding import bdecode, bencode
from pyto.messages import Message, KeepAlive, Choke, Unchoke, Interested, NotInterested, Have, \
                          BitField, Request, Piece, Cancel, Port, HandShake
from pyto.peer import Peer, exchange, PeerConnectErrors
from pyto.piecemanager import PieceManager


module_logger = logging.getLogger(__name__)


class TorrentAdapter(logging.LoggerAdapter):
    """Add the name of the Torrent to logger messages"""
    def process(self, msg, kwargs):
        return '{:>20} {}'.format(self.extra['name'], msg), kwargs


class Torrent:
    """Represent a Torrent file"""
    def __init__(self, announce: str, name: str, info_hash: bytes, hashes: List[bytes],
                 piece_length: int, length: int):
        self.announce = announce
        self.name = _sanitize(name)
        self.info_hash = info_hash
        self.hashes = hashes
        self.length = length
        self.piece_manager = PieceManager(length, piece_length)
        self.file = None

        self.server = None
        self.peers = dict([])
        self.blacklist = dict([])
        self.pending = dict([])

        self.futures = set([])

        self.logger = TorrentAdapter(module_logger, {'name': self.name})
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
             " piece_length: {}".format(self.piece_manager.default_piece_length),
             "   nbr_pieces: {}".format(self.piece_manager.nbr_pieces),
             "       pieces: {}".format(self.piece_manager.pieces),
        ])

    def read_piece(self, piece_index: int) -> bytes:
        self.logger.debug("reading piece #{}".format(piece_index))
        offset = piece_index * self.piece_manager.default_piece_length
        self.file.seek(offset)
        current_piece_length = self.piece_manager.piece_length(piece_index)
        return self.file.read(current_piece_length)

    def _seek_and_write(self, piece_index: int, piece: bytes):
        self.file.seek(piece_index * self.piece_manager.default_piece_length)
        self.file.write(piece)

    async def write_piece(self, loop):
        my_pieces_to_write = self.piece_manager.pieces_to_write.copy()
        self.piece_manager.pieces_to_write = dict([])
        for piece_index, piece in my_pieces_to_write.items():
            self.logger.debug("writing piece #{}".format(piece_index))
            await asyncio.wait_for(
                loop.run_in_executor(None, self._seek_and_write, piece_index, piece),
                timeout=None
            )

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
            pieces = iter(lambda: f.read(self.piece_manager.default_piece_length), b"")
            for piece_index, piece in enumerate(pieces):
                if self.hashes[piece_index] == sha1(piece).digest():
                    self.piece_manager.register_piece_owned(piece_index)
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

        if (p.ip, p.port) not in self.peers:
            self.peers[(p.ip, p.port)] = p

    def remove_peer(self, p: Peer):
        self.piece_manager.remove_peer(p.id, p.pieces)
        del self.peers[(p.ip, p.port)]

    def is_complete(self):
        all_pieces = set(range(self.piece_manager.nbr_pieces))
        self.logger.debug("missing pieces: {}".format(all_pieces - self.piece_manager.pieces))
        return self.piece_manager.pieces == all_pieces

    def build_answer_to(self, message: Message, peer_id: int, initiated: bool) -> List[Message]:
        handler_name = '_build_answer_to_' + message.__class__.__name__
        try:
            handler = getattr(self, handler_name)
        except AttributeError:
            self.logger.error("No handler found for message: {}".format(message))
            raise NotImplemented
        return handler(message, initiated, peer_id)

    def _build_answer_to_HandShake(self, message: HandShake, peer_id: int, initiated) -> List[Message]:
        if initiated:
            return []
        else:
            return [
                HandShake(self.info_hash),
                BitField(self.piece_manager.pieces, self.piece_manager.nbr_pieces)
            ]

    def _build_answer_to_Choke(self, message: Choke, peer_id: int, _) -> List[Message]:
        return []

    def _build_answer_to_Unchoke(self, message: Unchoke, peer_id: int, _) -> List[Message]:
        return []

    def _build_answer_to_Interested(self, message: Interested, peer_id: int, _) -> List[Message]:
        # TODO: update peer status
        return [Unchoke()]

    def _build_answer_to_NotInterested(self, message: NotInterested, peer_id: int, _) -> List[Message]:
        # TODO: update peer status
        return [Choke()]

    def _build_answer_to_Have(self, message: Have, peer_id: int, _) -> List[Message]:
        return []

    def _build_answer_to_BitField(self, message: BitField, peer_id: int, _) -> List[Message]:
        # Check if the peer has any interesting piece
        try:
            self.piece_manager.next_block(message.pieces, peer_id)
            return [Interested()]
        except IndexError:
            return []

    def _build_answer_to_Request(self, message: Request, peer_id: int, _) -> List[Message]:
        block = b""
        return [
            Piece(16384,
                  message.piece_index,
                  message.block_offset,
                  block)
        ]

    def _build_answer_to_Piece(self, message: Piece, peer_id: int, _) -> List[Message]:
        if message.piece_index in self.piece_manager.pieces:
            return [Have(message.piece_index)]
        else:
            return []

    def _build_answer_to_Port(self, message: Port, peer_id: int, _) -> List[Message]:
        return []

    def _build_answer_to_Cancel(self, message: Cancel, peer_id: int, _) -> List[Message]:
        return []

    def _build_answer_to_KeepAlive(self, message: KeepAlive, peer_id: int, _) -> List[Message]:
        return []

    def update_from_message(self, message: Message, peer_id: int):
        handler_name = '_update_from_' + message.__class__.__name__
        try:
            handler = getattr(self, handler_name)
        except AttributeError:
            self.logger.error("No handler found for message: {}".format(message))
            raise NotImplemented
        handler(message, peer_id)

    def _update_from_HandShake(self, message: HandShake, peer_id: int):
        if self.info_hash != message.info_hash:
            raise ValueError("Invalid HandShake message")

    def _update_from_Choke(self, message: Choke, peer_id: int):
        pass

    def _update_from_Unchoke(self, message: Unchoke, peer_id: int):
        pass

    def _update_from_Interested(self, message: Interested, peer_id: int):
        pass

    def _update_from_NotInterested(self, message: NotInterested, peer_id: int):
        pass

    def _update_from_Have(self, message: Have, peer_id: int):
        self.piece_manager.register_peer_has(message.piece_index)

    def _update_from_BitField(self, message: BitField, peer_id: int):
        for piece_index in message.pieces:
            self.piece_manager.register_peer_has(piece_index)

    def _update_from_Request(self, message: Request, peer_id: int):
        pass

    def _update_from_Piece(self, message: Piece, peer_id: int):
        self.piece_manager.register_block_received(message.piece_index,
                                                   message.block_offset,
                                                   message.block,
                                                   peer_id)
        if message.piece_index in self.piece_manager.pieces_to_write:
            piece = self.piece_manager.pieces_to_write[message.piece_index]
            if self.hashes[message.piece_index] != sha1(piece).digest():
                self.logger.error("Hashing failed for piece #{}".format(message.piece_index))
                # TODO: remove the piece from the piece_manager
                raise ValueError("Invalid piece")

            self.logger.debug("Hashing succeeded for piece #{}".format(message.piece_index))

            if self.is_complete():
                # TODO: reopen files in read-only mode
                self.logger.debug("Download complete. Nothing more to request")
                try:
                    self.queue.put_nowait("EVENT_DOWNLOAD_COMPLETE")
                except asyncio.QueueFull:
                    self.logger.warning("Queue full, could not write event")

    def _update_from_Port(self, message: Port, peer_id: int):
        pass

    def _update_from_Cancel(self, message: Cancel, peer_id: int):
        pass

    def _update_from_KeepAlive(self, message: KeepAlive, peer_id: int):
        pass

    async def complement(self, message: Piece) -> Piece:
        loop = asyncio.get_event_loop()
        future = loop.run_in_executor(None, self.read_piece, message.piece_index)
        piece = await asyncio.wait_for(future, timeout=None)
        block = piece[message.block_offset:message.block_offset+message.block_length]
        return Piece(len(block),
                     message.piece_index,
                     message.block_offset,
                     block)

    def build_requests(self, peer: Peer):
        """Build a list of request to be sent to the peer

        Side effect: update the list of pending piece of the Torrent instance"""
        if peer.chokes_me:
            return []

        reqs = []
        for _ in range(len(peer.pending), peer.pending_target, 1):
            try:
                piece_index, block_offset = self.piece_manager.next_block(peer.pieces, peer.id)
            except IndexError:
                break

            self.piece_manager.register_block_requested(piece_index, block_offset, peer.id)
            block_length = self.piece_manager.block_length(piece_index, block_offset)
            reqs.append(Request(piece_index, block_offset, block_length))
        return reqs

    def stop(self):
        print(self.futures)
        self.queue.put_nowait("EVENT_END")
        self.logger.info("EVENT_END")
        self.server.close()
        # End connections with peers
        for peer in self.peers.values():
            peer.close()
        self.file.close()


def init(torrent_file: str, download_dir: str):
    torrent = Torrent.from_file(torrent_file)
    torrent.init_files(download_dir)
    logging.debug(torrent)
    return torrent


async def download(torrent: Torrent, listen_port: int):
    # Schedule a connection to each peer
    pending_connections = set()
    for ip, port in torrent.get_peers():
        f = asyncio.ensure_future(Peer.from_ip(ip, port))
        torrent.futures.add(f)
        pending_connections.add(f)

    # Setup a server to accept incoming connections
    def accept_callback(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        ip, port = writer.get_extra_info('peername')
        p = Peer(ip, port, reader, writer)
        f = asyncio.ensure_future(exchange(torrent, p, initiated=False))
        torrent.futures.add(f)

    torrent.server = await asyncio.start_server(accept_callback, host="", port=listen_port)
    f = asyncio.ensure_future(torrent.server.wait_closed())
    torrent.futures.add(f)
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
            except PeerConnectErrors:
                pass
            # We catch ALL exceptions here, otherwise one of our futures may fail silently
            except Exception:
                torrent.logger.exception("Future failed")
                torrent.stop()
                raise
            else:
                if item in pending_connections:
                    p = result
                    f = asyncio.ensure_future(exchange(torrent, p, initiated=True))
                    torrent.futures.add(f)
                    pending_connections.remove(item)

    print(torrent.futures)
    torrent.stop()


def _split(l: List, n: int) -> List:
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


def _decode_ipv4(buffer: bytes) -> Tuple[str, int]:
    try:
        ip_str, port = unpack(">4sH", buffer)
        ip = ".".join([str(n) for n, in iter_unpack(">B", ip_str)])
        return ip, port
    except struct_error:
        pass
    raise ValueError("Invalid (ip, port)")


if __name__ == '__main__':
    pass
