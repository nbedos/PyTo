"""
Main module for PyTo

This is where we define the main classes:
    Torrent: represents a torrent file
    Peer: represents a member of the network

Executing this module launches the download of the last Archlinux installation file and is a good
way to see PyTo working.
"""
import urllib.request
import urllib.parse
from hashlib import sha1
import asyncio
import logging
import os
from struct import unpack, iter_unpack, error as struct_error
from typing import Iterator, Tuple

from BEncoding import bdecode, bencode
from Messages import Message, HandShake, Have, BitField


class Peer:
    buffer_size = 4096

    def __init__(self, torrent, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        self.reader = reader
        self.writer = writer
        self.ip, self.port = self.writer.get_extra_info('peername')

        self.torrent = torrent
        self.choking = True
        self.choked = True
        self.interested = False
        self.bitfield = bytearray(b"\x00"*torrent.bitfield_size)

    def __repr__(self):
        return "Peer({}:{}, choking={}, choked={})".format(self.ip,
                                                           self.port,
                                                           self.choking,
                                                           self.choked)

    @classmethod
    async def from_ip(cls, loop, torrent, ip: str, port: int):
        """Generate an instance of Peer from an ip address"""
        try:
            reader, writer = await asyncio.open_connection(ip, port, loop=loop)
        except (ConnectionRefusedError,
                ConnectionAbortedError,
                ConnectionError,
                ConnectionResetError,
                TimeoutError,
                OSError) as e:
            logging.debug("[{}:{}] Exception: {}".format(ip, port, e))
            return None
        return cls(torrent, reader, writer)

    async def read(self, buffer=b""):
        """"Generator returning the Messages received from the peer"""
        logging.debug("[{}:{}] Buffer before: {}".format(self.ip, self.port, str(buffer)))
        while self.reader:
            try:
                buffer += await self.reader.read(Peer.buffer_size)
            except (ConnectionRefusedError,
                    ConnectionAbortedError,
                    ConnectionError,
                    ConnectionResetError,
                    TimeoutError,
                    OSError) as e:
                logging.debug("[{}:{}] Exception: {}".format(self.ip, self.port, e))
                self.close()
                break

            if self.reader.at_eof():
                self.close()
                break

            logging.debug("[{}:{}] Buffer during: {}".format(self.ip, self.port, str(buffer)))
            while buffer:
                try:
                    message, buffer = Message.from_bytes(buffer)
                    if message is None:
                        break
                    else:
                        logging.debug("[{}:{}] Message received: {}".format(self.ip,
                                                                            self.port,
                                                                            str(message)))
                        logging.debug(
                            "[{}:{}] Buffer after: {}".format(self.ip, self.port, str(buffer)))
                        yield message
                except ValueError:
                    logging.error("[{}:{}] Received invalid message: {}".format(self.ip,
                                                                                self.port,
                                                                                str(buffer)))
                    self.close()
                    break

    def write(self, message):
        logging.debug("[{}:{}] write: {}".format(self.ip, self.port, str(message)))
        # TODO: Check exceptions
        self.writer.write(message.to_bytes())

    def close(self):
        logging.debug("[{}:{}] Connection closed".format(self.ip, self.port))
        if self.writer:
            self.writer.close()
        self.writer = None
        self.reader = None

    async def exchange(self, torrent):
        self.write(HandShake(torrent.info_hash))

        # TODO: Find the right syntax to read a single value from an asynchronous generator
        async for message in self.read():
            if not isinstance(message, HandShake):
                logging.debug("[{}:{}] HandShake failed (invalid message)".format(self.ip, self.port))
                if message.info_hash != self.torrent.info_hash:
                    logging.debug(("[{}:{}] HandShake failed "
                                   "(invalid info_hash: {})").format(self.ip,
                                                                     self.port,
                                                                     message.info_hash))
            break

        async for message in self.read():
            self.torrent.handle_message(message, self)


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


class Torrent:
    def __init__(self, torrent_file):
        # TODO: Check if all necessary keys are in the info dictionary
        with open(torrent_file, "rb") as f:
            m = bdecode(f.read())
        try:
            self.announce = m[b'announce']
            self.info = m[b'info']
            self.name = _sanitize(self.info[b'name'].decode("utf-8"))
            self.info_hash = sha1(bencode(self.info)).digest()

            self.piece_length = self.info[b"piece length"]
            self.hashes = _split(self.info[b"pieces"], 20)
            self.length = self.info[b"length"]
            q, r = divmod(self.length, self.piece_length)
            self.nbr_pieces = q + int(bool(r))
            q, r = divmod(self.nbr_pieces, 8)
            self.bitfield_size = q + int(bool(r))
            self.bitfield = bytearray(b"\x00" * self.bitfield_size)

            self.blocks = {}
            self.peers = dict([])
            self.blacklist = dict([])
            return
        except KeyError:
            pass
        raise ValueError("Invalid torrent file")

    def __repr__(self):
        return "\n\t".join([
             "Torrent: {}".format(self.name),
             "announce: {}".format(self.announce.decode()),
             "length: {}".format(self.length),
             "piece_length: {}".format(self.piece_length),
             "nbr_pieces: {}".format(self.nbr_pieces)
        ])

    def init_files(self, download_dir: str):
        """Create missing files, check existing ones"""
        os.makedirs(download_dir, exist_ok=True)
        torrent_file = os.path.join(download_dir, str(self.name))

        try:
            with open(torrent_file, "rb") as f:
                pieces = iter(lambda: f.read(self.piece_length), b"")
                for piece_index, piece in enumerate(pieces):
                    # TODO: Check for IndexError. The file size may not match len(self.hashes)
                    if self.hashes[piece_index] == sha1(piece).digest():
                        # The bit at position piece_index is also the
                        # r-th bit of the q-th byte. Set it to 1.
                        q, r = divmod(piece_index, 8)
                        self.bitfield[q] += (128 >> r)
        except FileNotFoundError:
            with open(torrent_file, "wb") as f:
                f.truncate(self.length)

    def get_peers(self) -> Iterator[Tuple[str, int]]:
        """Send an announce query to the tracker"""
        h = {
            'info_hash': self.info_hash,
            'peer_id': "-HT00000000000000000",
            'port': 6881,
            'uploaded': 0,
            'downloaded': 0,
            'left': self.info[b'length'],
            'event': "started",
            'compact': 1
        }

        url = "{}?{}".format(self.announce.decode(), urllib.parse.urlencode(h))
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

    def handle_message(self, message: Message, peer: Peer):
        if isinstance(message, BitField):
            if message.bitfield_size == self.bitfield_size:
                peer.bitfield = bytearray(message.bitfield)
            else:
                raise ValueError("Invalid BitField message")
        elif isinstance(message, Have):
            try:
                q, r = divmod(message.piece_index, 8)
                peer.bitfield[q] += (128 >> r)
            except IndexError:
                raise ValueError("Invalid Have message")


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
    t = Torrent(torrent_file)
    t.init_files(download_dir)
    logging.debug(t)
    peers = t.get_peers()
    logging.debug(t.peers)

    return [asyncio.start_server(lambda r, w: handle_connection(t, r, w),
                                       host='localhost',
                                       port=listen_port,
                                       loop=loop)] + \
           [wrapper(loop, t, ip, port) for ip, port in peers]



if __name__ == '__main__':
    logging.basicConfig(format='%(asctime)s %(message)s', level=logging.DEBUG)
    loop = asyncio.get_event_loop()

    c1 = download(loop, "./data/Torrent files/archlinux-2017.11.01-x86_64.iso.Torrent", 6881,
             os.path.expanduser("~/PyTo1"))

    loop.run_until_complete(asyncio.gather(*c1))
    loop.close()
