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
from struct import pack

from BEncoding import bdecode, bencode
from Messages import *


class Peer:
    buffer_size = 4096

    def __init__(self, buffer: bytes, bitfield_size: int):
        ip_1, ip_2, ip_3, ip_4, port = unpack(">4BH", buffer)
        self.ip = "{}.{}.{}.{}".format(ip_1, ip_2, ip_3, ip_4)
        self.port = port
        self.choking = True
        self.choked = True
        self.interested = False
        self.bitfield = bytearray(b"\x00"*bitfield_size)
        self.reader = None
        self.writer = None

    def __repr__(self):
        return "Peer({}:{}, choking={}, choked={})".format(self.ip,
                                                           self.port,
                                                           self.choking,
                                                           self.choked)

    async def connect(self, loop):
        """Initiate the connection with the peer"""
        logging.debug("[{}:{}] Initiating TCP connection...".format(self.ip, self.port))
        try:
            self.reader, self.writer = await asyncio.open_connection(self.ip, self.port, loop=loop)
            logging.debug("[{}:{}] Connected!".format(self.ip, self.port))
        except (ConnectionRefusedError,
                ConnectionAbortedError,
                ConnectionError,
                ConnectionResetError,
                TimeoutError,
                OSError) as e:
            logging.debug("[{}:{}] Exception: {}".format(self.ip, self.port, e))
            self.close()
            return

    async def read(self, buffer=b""):
        """"Generator returning the Messages sent by the peer"""
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

    async def exchange(self, loop: asyncio.AbstractEventLoop, torrent):
        await self.connect(loop)
        if self.reader is None:
            return

        self.write(HandShake(t.info_hash))

        # TODO: Find the right syntax to read a single value from an asynchronous generator
        async for message in self.read():
            if not isinstance(message, HandShake):
                logging.debug("[{}:{}] HandShake failed (invalid message)".format(self.ip, self.port))
                if message.info_hash != torrent.info_hash:
                    logging.debug(("[{}:{}] HandShake failed "
                                   "(invalid info_hash: {})").format(self.ip,
                                                                     self.port,
                                                                     message.info_hash))
            break

        async for message in self.read():
            torrent.handle_message(message, self)


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


def _sanitize(filename: list):
    allowed_characters = {' ', '-', '[', ']', '}', '{', '_', '.'}
    return "".join([c for c in filename if c.isalnum() or c in allowed_characters]).rstrip()


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
            self.peers = []
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

    def init_files(self):
        """Create missing files, check existing ones"""
        torrent_dir = os.path.expanduser("~/PyTo")
        os.makedirs(torrent_dir, exist_ok=True)
        torrent_file = os.path.join(torrent_dir, str(self.name))

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

    def tracker_get(self):
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
            self.peers = list(map(lambda b: Peer(b, self.bitfield_size), _split(d[b"peers"], 6)))

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


if __name__ == '__main__':
    logging.basicConfig(format='%(asctime)s %(message)s', level=logging.DEBUG)
    t = Torrent("./data/Torrent files/archlinux-2017.11.01-x86_64.iso.Torrent")
    t.init_files()

    logging.debug(t)
    t.tracker_get()
    logging.debug(t.peers)

    loop = asyncio.get_event_loop()
    coroutines = map(lambda p: p.exchange(loop, t), t.peers)
    loop.run_until_complete(asyncio.gather(*coroutines))

    loop.close()
