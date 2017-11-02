import urllib.request
import urllib.parse
from hashlib import sha1
import asyncio
import logging

from BEncoding import bdecode, bencode
from Messages import *


class Peer:
    def __init__(self, buffer: bytes, bitfield_size: int):
        ip_1, ip_2, ip_3, ip_4, port = unpack(">4BH", buffer)
        self.ip = "{}.{}.{}.{}".format(ip_1, ip_2, ip_3, ip_4)
        self.port = port
        self.choking = True
        self.choked = True
        self.interested = False
        self.bitfield = bytearray(b"\x00"*bitfield_size)

    def __repr__(self):
        return "Peer({}:{}, choking={}, choked={})".format(self.ip,
                                                           self.port,
                                                           self.choking,
                                                           self.choked)


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


class Torrent:
    def __init__(self, torrent_file):
        # TODO: Check if all necessary keys are in the info dictionary
        with open(torrent_file, "rb") as f:
            m = bdecode(f.read())
        try:
            self.announce = m[b'announce']
            self.info = m[b'info']
            self.name = self.info[b'name']
            self.info_hash = sha1(bencode(self.info)).digest()

            self.piece_length = self.info[b"piece length"]
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
                peer.bitfield[q] = pow(2, r)
            except IndexError:
                raise ValueError("Invalid Have message")


async def tcp_handshake(peer: Peer, loop, torrent: Torrent):
    header = "[%r:%d] " % (peer.ip, peer.port)
    buffer_size = 4096
    logging.debug(header + "Connecting...")

    try:
        reader, writer = await asyncio.open_connection(peer.ip, peer.port, loop=loop)
        logging.debug(header + "Connected!")

        message = HandShake(t.info_hash).to_bytes()
        logging.debug(header + "Send: " + str(message))
        writer.write(message)

        data = await reader.read(buffer_size)
    except (ConnectionRefusedError,
            ConnectionAbortedError,
            ConnectionError,
            ConnectionResetError,
            TimeoutError,
            OSError) as e:
        print("[{}:{}] Exception: {}".format(peer.ip, peer.port, e))
        return

    try:
        HandShake.from_bytes(data[0:68])
        buffer = data[68:]

    except ValueError:
        logging.debug(header + "Handshake failed")
        writer.close()
        logging.debug(header + "Closed socket")
        return

    while True:
        message, buffer = Message.from_bytes(buffer)
        if message is not None:
            logging.debug(header + "Received: " + str(message))
            torrent.handle_message(message, peer)

        try:
            data = await reader.read(buffer_size)
            if reader.at_eof():
                break
        except (ConnectionRefusedError,
                ConnectionAbortedError,
                ConnectionError,
                ConnectionResetError,
                TimeoutError,
                OSError) as e:
            print("[{}:{}] Exception: {}".format(peer.ip, peer.port, e))
            break

        buffer = buffer + data

    writer.close()
    logging.debug(header + "Closed socket")


if __name__ == '__main__':
    logging.basicConfig(format='%(asctime)s %(message)s', level=logging.DEBUG)

    t = Torrent("./data/Torrent files/archlinux-2017.10.01-x86_64.iso.Torrent")
    logging.debug(t)
    t.tracker_get()
    logging.debug(t.peers)

    loop = asyncio.get_event_loop()
    coroutines = map(lambda p: tcp_handshake(p, loop, t), t.peers)
    loop.run_until_complete(asyncio.gather(*coroutines))

    loop.close()
