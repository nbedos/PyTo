"""
Torrent module

An instance of the Torrent class represents a Torrent file
"""
import urllib.request
import urllib.parse
import asyncio
import logging
import os

from hashlib import sha1
from struct import unpack, iter_unpack, error as struct_error
from typing import Iterator, Tuple, Union, List

from BEncoding import bdecode, bencode
from Messages import Message, KeepAlive, Choke, Unchoke, Interested, NotInterested, Have, \
                     BitField, Request, Piece, Cancel, Port, HandShake
from Peer import Peer


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
        q, r = divmod(self.nbr_pieces, 8)
        self.bitfield_size = q + int(bool(r))
        self.bitfield = bytearray(b"\x00" * self.bitfield_size)
        self.file = None

        self.blocks = {}
        self.peers = dict([])
        self.blacklist = dict([])
        self.pending = dict([])

    @classmethod
    def from_file(cls, torrent_file):
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

    def __repr__(self):
        return "\n\t".join([
             "Torrent: {}".format(self.name),
             "    info_hash: {}".format(self.info_hash),
             "     announce: {}".format(self.announce),
             "       length: {}".format(self.length),
             " piece_length: {}".format(self.piece_length),
             "   nbr_pieces: {}".format(self.nbr_pieces),
             "     bitfield: {}".format(self.bitfield),
             "bitfield_size: {}".format(self.bitfield_size),
        ])

    def read_piece(self, piece_index: int) -> bytes:
        offset = piece_index * self.piece_length
        self.file.seek(offset)
        return self.file.read(self.piece_length)

    def write_piece(self, piece_index: int, piece: bytes):
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
                raise ValueError("The file size does not match with the torrent size")
            pieces = iter(lambda: f.read(self.piece_length), b"")
            for piece_index, piece in enumerate(pieces):
                if self.hashes[piece_index] == sha1(piece).digest():
                    # The bit at position piece_index is also the
                    # r-th bit of the q-th byte. Set it to 1.
                    q, r = divmod(piece_index, 8)
                    self.bitfield[q] += (128 >> r)
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
        logging.debug(url)
        with urllib.request.urlopen(url) as response:
            d = bdecode(response.read())
            return map(_decode_ipv4, _split(d[b"peers"], 6))

    def add_peer(self, p):
        if (p.ip, p.port) in self.blacklist:
            raise ValueError("This peer is blacklisted")

        # TODO: Is there a way to get an exception when inserting the key if it is already in the
        #  dictionary ?
        if (p.ip, p.port) not in self.peers:
            self.peers[(p.ip, p.port)] = p

    async def handle_message(self, message: Message, peer: Peer):
        default_block_length = pow(2, 14)
        if isinstance(message, KeepAlive):
            pass
        elif isinstance(message, Choke):
            peer.chokes_me = True
        elif isinstance(message, Unchoke):
            peer.chokes_me = False
        elif isinstance(message, Interested):
            peer.is_interested = True
        elif isinstance(message, NotInterested):
            peer.is_interested = False
        elif isinstance(message, Have):
            try:
                q, r = divmod(message.piece_index, 8)
                peer.bitfield[q] += (128 >> r)
            except IndexError:
                raise ValueError("Invalid Have message")
        elif isinstance(message, BitField):
            if message.bitfield_size == self.bitfield_size:
                peer.bitfield = bytearray(message.bitfield)

                r = self.request_new_piece(peer.bitfield)
                if r is not None:
                    peer.write(r)
            else:
                raise ValueError("Invalid BitField message")
        elif isinstance(message, Request):
            loop = asyncio.get_event_loop()
            done, not_done = await asyncio.wait([loop.run_in_executor(None,
                                                                      self.read_piece,
                                                                      message.piece_index)])
            results = [task.result() for task in done]
            piece = results.pop()
            block = piece[message.block_offset:message.block_offset+message.block_length]
            peer.write(Piece(len(block),
                             message.piece_index,
                             message.block_offset,
                             block))
        elif isinstance(message, Piece):
            if message.piece_index in self.pending:
                blocks = self.pending[message.piece_index]
                requested, block = blocks[message.block_offset]
                if requested:
                    blocks[message.block_offset] = (True, message.block)
                    missing_blocks = [(offset, requested) for offset, (requested, block) in
                                      blocks.items() if not block]
                    if missing_blocks:
                        unrequested_blocks = [offset for offset, requested in missing_blocks if
                                              not requested]
                        if unrequested_blocks:
                            offset = unrequested_blocks.pop()
                            blocks[offset] = (True, b"")
                            peer.write(Request(message.piece_index, offset, default_block_length))
                    else:
                        piece = b"".join([block for _, block in blocks.values()])
                        if self.hashes[message.piece_index] == sha1(piece).digest():
                            loop = asyncio.get_event_loop()
                            done, not_done = await asyncio.wait([
                                loop.run_in_executor(None,
                                                     self.write_piece,
                                                     message.piece_index,
                                                     piece)
                            ])
                            del self.pending[message.piece_index]
                            q, r = divmod(message.piece_index, 8)
                            self.bitfield[q] += (128 >> r)
                            peer.write(Have(message.piece_index))
                            r = self.request_new_piece(peer.bitfield)
                            if r is not None:
                                peer.write(r)
                            else:
                                pass
                        else:
                            del self.pending[message.piece_index]
                else:
                    pass
        elif isinstance(message, Cancel):
            pass
        elif isinstance(message, Port):
            pass

    def request_new_piece(self, peer_bitfield: bytes, block_length: int=16384) -> Union[Message,
                                                                                        None]:
        piece_index = _interesting_piece(self.bitfield, peer_bitfield, set(self.pending.keys()))
        if piece_index is None:
            return None

        if piece_index == self.nbr_pieces - 1:
            piece_length = self.length - self.piece_length * (self.nbr_pieces - 1)
        else:
            piece_length = self.piece_length

        q, r = divmod(piece_length, block_length)
        nbr_blocks = q + int(bool(r))
        self.pending[piece_index] = {
            (i * block_length): (False, b"") for i in range(0, nbr_blocks)
        }
        self.pending[piece_index][0] = (True, b"")

        return Request(piece_index, 0, block_length)


# TODO: Ignore trailing bits if the number of pieces is not divisible by 8
def _interesting_piece(b1: bytes, b2: bytes, index_blacklist: set) -> Union[None, int]:
    """Return the index of a bit which is set in b2 but not in b1"""
    z = map(lambda b: ((~ b[0]) & b[1]), zip(b1, b2))
    comparison = ((i, b) for i, b in enumerate(z) if b != 0 and i not in index_blacklist)
    try:
        byte_index, byte = next(comparison)
    except StopIteration:
        return None

    lowest_bit_set = 7 - next((i for i in range(7, -1, -1) if (byte >> i) & 1 != 0))

    return 8*byte_index + lowest_bit_set


async def handle_connection(torrent: Torrent, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    p = Peer(torrent, reader, writer)
    if p is not None:
        torrent.add_peer(p)
        await p.exchange(torrent)


async def wrapper(loop, torrent: Torrent, ip: str, port: int):
    p = await Peer.from_ip(loop, torrent, ip, port)
    if p is not None:
        torrent.add_peer(p)
        await p.exchange(torrent)


def download(loop, torrent_file: str, listen_port: int, download_dir: str):
    t = Torrent.from_file(torrent_file)
    t.init_files(download_dir)
    logging.debug(t)
    peers = t.get_peers()
    logging.debug(t.peers)

    return [asyncio.start_server(lambda r, w: handle_connection(t, r, w),
                                 host='localhost',
                                 port=listen_port,
                                 loop=loop)] + \
           [wrapper(loop, t, ip, port) for ip, port in peers]


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
