"""
Torrent module

An instance of the Torrent class represents a Torrent file
"""
import asyncio
import json
import logging
import os
import urllib.parse
import urllib.request

from hashlib import sha1
from struct import unpack, iter_unpack, error as struct_error
from typing import Iterator, Tuple, Union, List, Set

from BEncoding import bdecode, bencode
from Messages import Message, KeepAlive, Choke, Unchoke, Interested, NotInterested, Have, \
                     BitField, Request, Piece, Cancel, Port, HandShake
from Peer import Peer


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
        if piece_length <= 0 or piece_length > length:
            raise ValueError("Lengths must verify 0 < piece_length <= length")
        self.length = length
        self.piece_length = piece_length
        q, r = divmod(self.length, self.piece_length)
        self.nbr_pieces = q + int(bool(r))
        self.pieces = set([])
        self.file = None

        #self.blocks = {}
        self.peers = dict([])
        self.blacklist = dict([])
        self.pending = dict([])

        self.logger = TorrentAdapter(module_logger, {'name': self.name})

        self.futures = {}
        self.server = None

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

    def write_piece(self, piece_index: int, piece: bytes):
        self.logger.debug("writing piece #{}".format(piece_index))
        self.file.seek(piece_index * self.piece_length)
        self.file.write(piece)

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
                    # The bit at position piece_index is also the
                    # r-th bit of the q-th byte. Set it to 1.
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

    def is_complete(self):
        return self.pieces == set(range(0, self.nbr_pieces))

    async def handle_message(self, message: Message, peer_pieces: Set[int], peer_chokes: bool,
                             initiated: bool):
        if isinstance(message, HandShake):
            if self.info_hash == message.info_hash:
                if not initiated:
                    return [
                        HandShake(self.info_hash),
                        BitField(self.pieces, self.nbr_pieces)
                    ]
            else:
                raise ValueError("Invalid HandShake message")
        elif isinstance(message, Choke):
            pass
        elif isinstance(message, Unchoke):
            r = self.request_new_block(peer_pieces)
            if r is not None:
                return [r]
        elif isinstance(message, Interested):
            return [Unchoke()]
        elif isinstance(message, NotInterested):
            return [Choke()]
        elif isinstance(message, BitField):
            all_pieces = set(range(0, self.nbr_pieces))
            requestable_pieces = (all_pieces - self.pieces) & message.pieces
            if requestable_pieces:
                return [Interested()]
        elif isinstance(message, Request):
            loop = asyncio.get_event_loop()
            done, not_done = await asyncio.wait([loop.run_in_executor(None,
                                                                      self.read_piece,
                                                                      message.piece_index)])
            results = [task.result() for task in done]
            piece = results.pop()
            block = piece[message.block_offset:message.block_offset+message.block_length]
            return [
                Piece(len(block),
                      message.piece_index,
                      message.block_offset,
                      block)
            ]
        elif isinstance(message, Piece):
            try:
                blocks = self.pending[message.piece_index]
                _, _ = blocks[message.block_offset]
            except KeyError:
                self.logger.error("Received unrequested piece #{} offset {})".format(
                    message.piece_index, message.block_offset))
                return []

            blocks[message.block_offset] = (True, message.block)
            # Otherwise we may have all the blocks for this piece
            if all([block for _, block in blocks.values()]):
                piece = b"".join([block for _, block in blocks.values()])
                if self.hashes[message.piece_index] != sha1(piece).digest():
                    self.logger.error("Hashing failed for piece #{}".format(
                        message.piece_index))
                    del self.pending[message.piece_index]
                    return []

                self.logger.debug("Hashing succeeded for piece #{}".format(message.piece_index))
                loop = asyncio.get_event_loop()
                await asyncio.wait([
                    loop.run_in_executor(None, self.write_piece, message.piece_index, piece)
                ])

                del self.pending[message.piece_index]
                self.pieces.add(message.piece_index)

                self.logger.debug("Update list of pieces: {}".format(self.pieces))

                r = self.request_new_block(peer_pieces)
                if r is not None:
                    return [Have(message.piece_index), r]
                else:
                    self.logger.debug("No more blocks to request")
                    try:
                        self.queue.put_nowait("EVENT_DOWNLOAD_COMPLETE")
                    except asyncio.QueueFull:
                        self.logger.warning("Queue full, could not write event")
                    return [Have(message.piece_index)]
            else:
                r = self.request_new_block(peer_pieces)
                if r is not None:
                    return [r]
        return []

    def request_new_block(self, peer_pieces: Set[int], block_length: int=16384) -> Union[Request,
                                                                                         None]:
        """Build a Request message for a new block.

        If possible, return Request for a block which
            - is missing
            - belong to a piece owned by the peer
            - has not already been requested
        Otherwise return a Request for a block which has been requested but has not been received
        yet"""
        all_pieces = set(range(0, self.nbr_pieces))

        # Make a blacklist of the pieces which have all their blocks pending
        blacklist = set([p for p in self.pending.keys() if self.pending[p] and
                         all([requested for (requested, _) in self.pending[p].values()])])

        # Look for a missing block owned by the peer and not yet requested
        requestable_pieces = (all_pieces - self.pieces - blacklist) & peer_pieces
        try:
            piece_index = requestable_pieces.pop()
        except KeyError:
            # Otherwise, look for a missing block owned by the peer which may have already been
            # requested
            requestable_pieces = (all_pieces - self.pieces) & peer_pieces
            try:
                piece_index = requestable_pieces.pop()
            except KeyError:
                return None

        if piece_index == self.nbr_pieces - 1:
            # The last piece may be shorter than all the others
            piece_length = self.length - self.piece_length * (self.nbr_pieces - 1)
        else:
            piece_length = self.piece_length

        # If the piece is pending, pick the first non requested block
        if piece_index in self.pending:
            # Sort the pending blocks to get
            #   - First the non requested block (False, ...)
            #   - Then blocks we requested but have not received (True, b"")
            #   - Then blocks we've already downloaded (True, b"data...")
            sorted_blocks = sorted(self.pending[piece_index].items(), key=lambda x: x[1])
            not_requested = (offset for offset, (requested, b) in sorted_blocks if not requested
                             or not b)
            block_offset = next(not_requested)
        # If no block of this piece has been requested, pick the first one and initialize the
        # block list
        else:
            q, r = divmod(piece_length, block_length)
            nbr_blocks = q + int(bool(r))
            self.pending[piece_index] = {
                (i * block_length): (False, b"") for i in range(0, nbr_blocks)
            }
            block_offset = 0

        self.pending[piece_index][block_offset] = (True, b"")
        return Request(piece_index, block_offset, block_length)



def handle_connection(torrent: Torrent, reader: asyncio.StreamReader,
                            writer: asyncio.StreamWriter):
    p = Peer(reader, writer)
    if p is not None:
        torrent.logger.debug("accepted incoming connection from {}:{}".format(p.ip, p.port))
        f = asyncio.ensure_future(p.exchange(torrent, initiated=False))
        torrent.add_peer(p)
        torrent.futures[f] = True


# TODO : handle task cancelling gracefully
async def start_peer(loop, torrent: Torrent, ip: str, port: int):
    p = await Peer.from_ip(loop, ip, port)
    if p is not None:
        torrent.add_peer(p)
        await p.exchange(torrent, initiated=True)

def stop(torrent, loop):
    if torrent.file:
        torrent.file.close()

    for peer in torrent.peers.values():
        if peer.writer:
            peer.writer.close()

    if torrent.server:
        print('closing server')
        torrent.server.close()


def init(torrent_file: str, download_dir: str):
    torrent = Torrent.from_file(torrent_file)
    torrent.init_files(download_dir)
    logging.debug(torrent)
    return torrent

async def download(loop, torrent, listen_port: int):
    # start_server will set up a server listening on the given port and return
    # as soon as it is done. The value returned is an AbstractServer instance.
    # Then, handle_connection will be called to handle every incoming
    # connection.
    f = asyncio.ensure_future(
        asyncio.start_server(lambda r, w: handle_connection(torrent, r, w),
                             host='localhost',
                             port=listen_port,
                             loop=loop)
    )
    torrent.futures[f] = True

    if not torrent.is_complete():
        for ip, port in torrent.get_peers():
            f = asyncio.ensure_future(start_peer(loop, torrent, ip, port))
            torrent.futures[f] = True

    while torrent.futures:
        print(torrent.futures)
        try:
            done, futures = await asyncio.wait(torrent.futures.keys(), return_when=asyncio.FIRST_COMPLETED)
        except asyncio.CancelledError:
            break

        for item in done:
            if isinstance(item.result(), asyncio.AbstractServer):
                torrent.server = item.result()
                f = asyncio.ensure_future(torrent.server.wait_closed())
                torrent.futures[f] = False
                try:
                    torrent.queue.put_nowait("EVENT_ACCEPT_CONNECTIONS")
                except asyncio.QueueFull:
                    torrent.logger.warning("Queue full, could not write event")
            del torrent.futures[item]

    torrent.file.close()

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
