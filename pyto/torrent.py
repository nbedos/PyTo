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
from typing import Iterator, Tuple, Union, List, Set, Dict, BinaryIO

from pyto.bencoding import bdecode, bencode
from pyto.messages import Message, KeepAlive, Choke, Unchoke, Interested, NotInterested,\
                          Have, BitField, Request, Piece, Cancel, Port, HandShake
from pyto.peer import Peer, PeerConnectErrors, PeerWriteErrors
from pyto.piecemanager import PieceManager

module_logger = logging.getLogger(__name__)


class TorrentAdapter(logging.LoggerAdapter):
    """Add the name of the Torrent to logger messages"""

    def process(self, msg, kwargs):
        return '{:>20} {}'.format(self.extra['name'], msg), kwargs


# Schemas describing the metainfo dictionary format
METAINFO_SINGLE_FILE = {
    b'announce': b'bytestring',
    b'info': {
        b'name': b'bytestring',
        b'length': 0,
        b'pieces': b'bytestring',
        b'piece length': 0,
    }
}

METAINFO_MULTIPLE_FILES = {
    b'announce': b'bytestring',
    b'info': {
        b'files': [{
            b'path': [b'bytestring'],
            b'length': 0
        }],
        b'name': b'bytestring',
        b'pieces': b'bytestring',
        b'piece length': 0,
    }
}


class Torrent:
    """Represent a Torrent file"""

    def __init__(self, announce: str, name: str, contents, info_hash: bytes,
                 hashes: List[bytes], piece_length: int):
        self.announce = announce
        self.name = _sanitize(name)
        self.contents = contents
        self.structure = {}
        self.info_hash = info_hash
        self.hashes = hashes
        self.length = sum(file_length for _, _, file_length in contents)
        self.piece_manager = PieceManager(self.length, piece_length)
        self._is_complete = False

        self.server = None
        self.peers = dict([])
        self.blacklist = dict([])
        self.pending = dict([])

        self.futures = set([])

        self.logger = TorrentAdapter(module_logger, {'name': self.name})
        self.queue = asyncio.Queue(50)

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

    @classmethod
    async def create(cls, torrent_file: str, download_dir: str):
        """Create an instance of the Torrent class from a metainfo file and initialize all
        the necessary files on disk"""
        torrent = Torrent._from_file(torrent_file)
        await torrent.init_files(download_dir)
        logging.debug(torrent)
        return torrent

    @classmethod
    def _from_file(cls, torrent_file: str):
        """Create an instance of Torrent from a metainfo file"""
        with open(torrent_file, "rb") as f:
            m = bdecode(f.read())

        if _validate_structure(m, METAINFO_SINGLE_FILE):
            single_file_mode = True
        elif _validate_structure(m, METAINFO_MULTIPLE_FILES):
            single_file_mode = False
        else:
            raise ValueError("Invalid torrent file")

        info = m[b'info']
        info_hash = sha1(bencode(info)).digest()
        announce = m[b'announce'].decode("utf-8")
        name = info[b'name'].decode("utf-8")
        hashes = _split(info[b'pieces'], sha1().digest_size)
        piece_length = info[b'piece length']

        contents = []
        if single_file_mode:
            contents.append(("", _sanitize(name), info[b"length"]))
        else:
            for file_dict in info[b'files']:
                path_str = [_sanitize(b.decode("utf-8")) for b in file_dict[b'path']]
                directory = os.path.join("", *path_str[:-1])
                filename = path_str[-1]
                contents.append((directory, filename, file_dict[b'length']))

        return cls(announce, name, contents, info_hash, hashes, piece_length)

    async def init_files(self, download_dir: str):
        """Read all the torrent files on disk and check which pieces have been downloaded.
        If files are missing, create them together with the right directory structure
        """
        os.makedirs(download_dir, exist_ok=True)

        offset = 0
        just_created = True
        for dirname, filename, file_length in self.contents:
            file_directory = os.path.join(download_dir, dirname)
            os.makedirs(file_directory, exist_ok=True)
            file_path = os.path.join(file_directory, filename)
            # Opening a file in 'rb+' (read, write, binary) will raise FileNotFoundError
            # if the file is missing. So we have to open it in write only mode to create
            # the file, and then reopen it in 'rb+' mode.
            try:
                f = open(file_path, "rb+")
                if os.stat(file_path).st_size != file_length:
                    f.truncate(file_length)
            except FileNotFoundError:
                f = open(file_path, "wb")
                f.truncate(file_length)
                f.close()
                f = open(file_path, "rb+")
            else:
                just_created = False

            self.structure[(offset, offset + file_length - 1)] = (f, asyncio.Lock())
            offset += file_length

        if not just_created:
            owned_pieces = await self.check_pieces_on_disk()
            for piece_index in owned_pieces:
                self.piece_manager.register_piece_owned(piece_index)

            if owned_pieces == set(range(self.piece_manager.nbr_pieces)):
                self._is_complete = True
                # Reopen files in read only mode
                for key in self.structure:
                    file, lock = self.structure[key]
                    name = file.name
                    file.close()
                    self.structure[key] = open(name, 'rb'), lock

    @staticmethod
    def _seek_and_read(file: BinaryIO, part_offset: int, part_length: int):
        file.seek(part_offset)
        return file.read(part_length)

    async def read_piece(self, piece_index: int):
        """Read the requested piece from disk

        This function uses locks for synchronization with other disk operations.
        """
        self.logger.debug("reading piece #{}".format(piece_index))
        loop = asyncio.get_event_loop()
        piece_offset = piece_index * self.piece_manager.default_piece_length
        current_piece_length = self.piece_manager.piece_length(piece_index)
        piece_bounds = piece_offset, piece_offset + current_piece_length - 1
        piece = b""
        for file_bounds, (file, lock) in self.structure.items():
            file_offset, _ = file_bounds
            interval = _intersection(file_bounds, piece_bounds)
            if interval is not None:
                part_offset_in_file = interval[0] - file_offset
                part_length = interval[1] - interval[0] + 1
                with await lock:
                    piece += await loop.run_in_executor(None,
                                                        self._seek_and_read,
                                                        file,
                                                        part_offset_in_file,
                                                        part_length)
        return piece

    @staticmethod
    def _seek_and_write(file: BinaryIO, part_offset: int, part: bytes):
        file.seek(part_offset)
        file.write(part)

    async def write_pieces(self, loop):
        """Write on disk all the pieces saved in the torrent instance

        This function uses locks for synchronization with other disk operations.
        """
        my_pieces_to_write = self.piece_manager.pieces_to_write.copy()
        self.piece_manager.pieces_to_write = dict([])
        # TODO: We might lose pieces if we crash here
        for piece_index, piece in my_pieces_to_write.items():
            self.logger.debug("writing piece #{}".format(piece_index))
            piece_offset = piece_index * self.piece_manager.default_piece_length
            current_piece_length = self.piece_manager.piece_length(piece_index)
            piece_bounds = piece_offset, piece_offset + current_piece_length - 1
            for file_bounds, (file, lock) in self.structure.items():
                file_offset, _ = file_bounds
                interval = _intersection(file_bounds, piece_bounds)
                if interval is not None:
                    part_offset_in_file = interval[0] - file_offset
                    part_length = interval[1] - interval[0] + 1
                    part_offset_in_piece = part_offset_in_file - (piece_offset - file_offset)
                    part = piece[part_offset_in_piece: part_offset_in_piece + part_length]
                    with await lock:
                        await loop.run_in_executor(None,
                                                   self._seek_and_write,
                                                   file,
                                                   part_offset_in_file,
                                                   part)

    def get_peers(self) -> Iterator[Tuple[str, int]]:
        """Send an announce query to the tracker to get a list of peers"""
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

        ips = [(q.ip, q.port) for q in self.peers.values()]
        if (p.ip, p.port) not in ips:
            self.peers[p.id] = p

    def remove_peer(self, p: Peer):
        self.piece_manager.remove_peer(p.id, p.pieces)
        del self.peers[p.id]

    async def check_pieces_on_disk(self):
        """Return the list of pieces on disk which have a correct hash"""
        matching_pieces = set()
        for piece_index in range(self.piece_manager.nbr_pieces):
            piece = await self.read_piece(piece_index)
            if sha1(piece).digest() == self.hashes[piece_index]:
                matching_pieces.add(piece_index)
        return matching_pieces

    # FIXME: This function might be called multiple times and send several DOWNLOAD_COMPLETE
    # events
    async def is_complete(self):
        """Return True if the download is complete, false otherwise

        The first time this function is called after the download completes, all pieces are
        hashed and the hashes are compared to the content of the metainfo file. If all hashes
        match, all files are reopened in read only mode to prevent any modification."""
        if self._is_complete:
            return True

        all_pieces = set(range(self.piece_manager.nbr_pieces))
        self.logger.debug("missing pieces: {}".format(all_pieces - self.piece_manager.pieces))
        if self.piece_manager.pieces == all_pieces:
            self.logger.info("Checking pieces hashes...")
            matching_pieces = await self.check_pieces_on_disk()
            self._is_complete = (all_pieces == matching_pieces)
            if self._is_complete:
                self.logger.debug("Download complete. Nothing more to request")
                try:
                    self.queue.put_nowait("EVENT_DOWNLOAD_COMPLETE")
                except asyncio.QueueFull:
                    self.logger.warning("Queue full, could not write event")
                self.logger.info("EVENT_DOWNLOAD_COMPLETE")

                for key, (file, lock) in self.structure.items():
                    with await lock:
                        name = file.name
                        file.close()
                        file = open(name, 'rb')
                    self.structure[key] = (file, lock)

            else:
                self.logger.debug("invalid pieces: {}".format(all_pieces - matching_pieces))

            return self._is_complete

    def build_answer_to(self, message: Message, peer: Peer) -> List[Message]:
        handler_name = '_build_answer_to_' + message.__class__.__name__
        if hasattr(self, handler_name):
            handler = getattr(self, handler_name)
            return handler(message, peer)
        else:
            return []

    def _build_answer_to_HandShake(self, message: HandShake, peer) -> List[Message]:
        if peer.initiated:
            return [
                HandShake(self.info_hash),
                BitField(self.piece_manager.pieces, self.piece_manager.nbr_pieces)
            ]
        else:
            return []

    def _build_answer_to_Interested(self, *_) -> List[Message]:
        # TODO: update peer status
        return [Unchoke()]

    def _build_answer_to_NotInterested(self, *_) -> List[Message]:
        # TODO: update peer status
        return [Choke()]

    def _build_answer_to_BitField(self, message: BitField, peer: Peer) -> List[Message]:
        # Check if the peer has any interesting piece
        try:
            self.piece_manager.next_block(message.pieces, peer.id)
            return [Interested()]
        except IndexError:
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
        if message.piece_index in self.piece_manager.pieces:
            return [Have(message.piece_index)]
        else:
            return []

    def update_from_message(self, message: Message, peer_id: int):
        handler_name = '_update_from_' + message.__class__.__name__
        if hasattr(self, handler_name):
            handler = getattr(self, handler_name)
            return handler(message, peer_id)

    def _update_from_HandShake(self, message: HandShake, _):
        if self.info_hash != message.info_hash:
            raise ValueError("Invalid HandShake message")

    def _update_from_Have(self, message: Have, _):
        self.piece_manager.register_peer_has(message.piece_index)

    def _update_from_BitField(self, message: BitField, _):
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

    async def complement(self, message: Piece) -> Piece:
        piece = await self.read_piece(message.piece_index)
        block = piece[message.block_offset:message.block_offset + message.block_length]
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

    # FIXME: Change stop() not to send multiple events when the function is called multiple times
    async def stop(self):
        print(self.futures)
        self.queue.put_nowait("EVENT_END")
        self.logger.info("EVENT_END")
        if self.server is not None:
            self.server.close()
        # End connections with peers
        for peer in self.peers.values():
            peer.close()

        for file, lock in self.structure.values():
            with await lock:
                file.close()

    # TODO: Cleanly end connection when the task is cancelled
    async def exchange(self, p: Peer):
        """Exchange data with the peer"""
        loop = asyncio.get_event_loop()

        self.add_peer(p)
        self.logger.info("new peer added!")
        if not p.initiated:
            await p.write([
                HandShake(self.info_hash),
                BitField(self.piece_manager.pieces, self.piece_manager.nbr_pieces)
            ])

        async for message in p.get_messages():
            # Update the peer with information from the message
            try:
                p.handle_message(message)
            except ValueError as e:
                p.logger.error("invalid message: {}".format(str(e)))
                break

            # Update the torrent with information from the message
            self.update_from_message(message, p.id)

            # Commit pieces to disk
            if self.piece_manager.pieces_to_write:
                await self.write_pieces(loop)
                await self.is_complete()

            # Build a suitable answer
            messages = []
            for m in self.build_answer_to(message, p):
                if isinstance(m, Piece):
                    # Read disk to add missing info
                    messages.append(await self.complement(m))
                else:
                    messages.append(m)

            # Add requests
            messages += self.build_requests(p)

            # Update peer with messages to be sent
            for m in messages:
                if isinstance(m, Request):
                    p.pending.add((m.piece_index, m.block_offset))

            # Send messages
            try:
                await p.write(messages)
            except PeerWriteErrors as e:
                p.logger.debug("write() failed: {}".format(str(e)))
                break

        self.remove_peer(p)
        p.close()

    async def download(self, listen_port: int):
        # Schedule a connection to each peer
        pending_connections = set()
        for ip, port in self.get_peers():
            f = asyncio.ensure_future(Peer.from_ip(ip, port))
            self.futures.add(f)
            pending_connections.add(f)

        # Setup a server to accept incoming connections
        def accept_callback(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
            ip, port = writer.get_extra_info('peername')
            p = Peer(ip, port, reader, writer)
            f = asyncio.ensure_future(self.exchange(p))
            self.futures.add(f)

        self.server = await asyncio.start_server(accept_callback, host="", port=listen_port)
        f = asyncio.ensure_future(self.server.wait_closed())
        self.futures.add(f)
        try:
            self.queue.put_nowait("EVENT_ACCEPT_CONNECTIONS")
            self.logger.info("EVENT_ACCEPT_CONNECTIONS")
        except asyncio.QueueFull:
            self.logger.warning("Queue full, could not write event")

        while self.futures:
            try:
                done, self.futures = await asyncio.wait(self.futures,
                                                        return_when=asyncio.FIRST_COMPLETED)
            except asyncio.CancelledError:
                break

            for item in done:
                try:
                    result = item.result()
                except asyncio.CancelledError:
                    self.logger.info("Task cancelled: {}".format(item))
                except PeerConnectErrors:
                    pass
                # We catch ALL exceptions here, otherwise one of our futures may fail silently
                except Exception:
                    self.logger.exception("Future failed")
                    await self.stop()
                    raise
                else:
                    if item in pending_connections:
                        p = result
                        f = asyncio.ensure_future(self.exchange(p))
                        self.futures.add(f)
                        pending_connections.remove(item)

        print(self.futures)
        await self.stop()


def _split(l: List, n: int) -> List:
    """Split the list l in chunks of size n"""
    if n < 0:
        raise ValueError("n must be >= 0")
    i = 0
    chunks = []
    while l[i:i + n]:
        chunks.append(l[i:i + n])
        i = i + n
    return chunks


def _sanitize(filename: str) -> str:
    """Remove potentially treacherous characters from a path name"""
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


def _intersection(interval1: Tuple[int, int], interval2: Tuple[int, int]):
    """Return the intersection of two closed intervals as an interval

    If the two intervals do not overlap, return None"""
    (a, b), (c, d) = interval1, interval2
    assert (a <= b) and (c <= d)

    lower_bound = max(a, c)
    upper_bound = min(b, d)

    if lower_bound <= upper_bound:
        return lower_bound, upper_bound

    return None


def _path_components(mypath: str) -> List[str]:
    """Return the list of components in mypath:
        _path_components("A/B/C/D") = ['A', 'B', 'C', 'D']
    """
    components = []
    head = mypath
    while True:
        head, tail = os.path.split(head)
        if tail:
            components.insert(0, tail)
        else:
            if head:
                components.insert(0, head)
            break

    return components


def metainfo(directory: str, piece_length: int, announce: str) -> Dict:
    """Return a metainfo dictionary describing the content of the directory"""
    buffer = b''
    hashes = []
    filestats = []
    directory = os.path.realpath(directory)
    for dirpath, _, filenames in os.walk(directory, topdown=False):
        for filename in filenames:
            full_path = os.path.join(dirpath, filename)
            relative_path = os.path.relpath(full_path, directory)
            filestats.append({
                b'path': [c.encode('utf-8') for c in _path_components(relative_path)],
                b'length': os.path.getsize(full_path)
            })
            with open(full_path, "rb") as f:
                while True:
                    data = f.read(piece_length - len(buffer))
                    if not data:
                        break
                    buffer += data
                    if len(buffer) == piece_length:
                        hashes.append(sha1(buffer).digest())
                        buffer = b''
    if buffer:
        hashes.append(sha1(buffer).digest())

    m = {
        b'announce': announce.encode('utf-8'),
        b'info': {
            b'pieces': b"".join(hashes),
            b'piece length': piece_length,
        }
    }

    # Single file mode if there is only 1 file in the current directory (no directory structure)
    if len(filestats) == 1 and len(filestats[0][b'path']) == 1:
        m[b'info'][b'name'] = filestats[0][b'path'][0]
        m[b'info'][b'length'] = filestats[0][b'length']
    # Multiple files mode otherwise
    else:
        _, tail = os.path.split(directory)
        m[b'info'][b'name'] = os.path.basename(tail).encode('utf-8')
        m[b'info'][b'files'] = filestats
    return m


def _validate_structure(data, schema) -> bool:
    """Check if the structure of 'data' conforms to 'schema'

    'schema' is a (minimal) data structure such as for example:
        s = {'announce': 'text', 'length': 1}

    Dictionaries in 'data' may have keys not found in schema

    Restriction: Elements of lists are checked against the first element of the corresponding
    list in schema: this makes it impossible to validate lists containing different types"""
    if isinstance(data, dict) and isinstance(schema, dict):
        tests = [key in data and _validate_structure(data[key], schema[key]) for key in schema]
        return all(tests)
    elif isinstance(data, list):
        tests = [_validate_structure(value, schema[0]) for value in data]
        return all(tests)
    else:
        return isinstance(data, type(schema))


if __name__ == '__main__':
    pass

