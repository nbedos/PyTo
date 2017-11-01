from BEncoding import bdecode, bencode
import urllib.request
import urllib.parse
from hashlib import sha1
import asyncio
from Messages import *


class peer:
    def __init__(self, ip: str, port: int, bitfield_size: int):
        self.ip = ip
        self.port = port
        self.choking = True
        self.choked = True
        self.interested = False
        self.bitfield = bytearray(b"\x00"*bitfield_size)

    def __repr__(self):
        return "peer({}:{}, choking={}, choked={})".format(self.ip,
                                                           self.port,
                                                           self.choking,
                                                           self.choked)

    #TODO: useless ??
    @classmethod
    def from_compact_ipv4(cls, buffer, bitfield_size):
        ip_1, ip_2, ip_3, ip_4, port = unpack(">4BH", buffer)
        ipv4 = "{}.{}.{}.{}".format(ip_1, ip_2, ip_3, ip_4)
        return peer(ipv4, port, bitfield_size)


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

#TODO: duplicate
def _bytes_to_ipv4_port(b: bytes) -> peer:
    #print(b)
    ipv4 = "{}.{}.{}.{}".format(int.from_bytes(b[0:1], "big"),
                                int.from_bytes(b[1:2], "big"),
                                int.from_bytes(b[2:3], "big"),
                                int.from_bytes(b[3:4], "big"))
    port = int.from_bytes(b[4:6], "big")
    #print("{}:{}".format(ipv4, port))
    return peer(ipv4, port)


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
        print(url)
        with urllib.request.urlopen(url) as response:
            d = bdecode(response.read())
            self.peers = list(map(lambda b: peer.from_compact_ipv4(b, self.bitfield_size),
                                  _split(d[b"peers"], 6)))


async def tcp_handshake(peer: peer, loop, torrent: Torrent):
    header = b"[%r:%d] " % (peer.ip, peer.port)
    buffer_size = 4096
    print(header + b"Connecting...")

    try:
        reader, writer = await asyncio.open_connection(peer.ip, peer.port, loop=loop)
        print(header + b"Connected!")

        message = HandShake(t.info_hash).to_bytes()
        print(header + b"Send: " + message)
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
        h = HandShake.from_bytes(data[0:68])
        buffer = data[68:]

    except ValueError:
        print(header + b"Handshake failed")
        writer.close()
        print(header + b"Closed socket")
        return

    while True:
        message, buffer = Message.from_bytes(buffer)
        if message is not None:
            print(header, buffer)
            print((header + b"Received: "), message)

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
        print(message)

    writer.close()
    print(header + b"Closed socket")

    def handle_message(self, message: Message, peer: peer):
        if isinstance(message, BitField):
            if message.bitfield_size == self.bitfield_size:
                peer.bitfield = bytearray(message.bitfield)
            else:
                raise ValueError("Invalid BitField message")
        elif isinstance(message, Have):
            try:
                q, r = divmod(message.piece_index, 8)
                peer.bitfield[q] = pow(2, r)
                print(peer.bitfield)
            except IndexError:
                raise ValueError("Invalid Have message")


if __name__ == '__main__':
    # t = Torrent("./data/Torrent files/archlinux-2017.10.01-x86_64.iso.Torrent")
    t = Torrent("./data/Torrent files/archlinux-2017.10.01-x86_64.iso.Torrent")
    print(t)
    t.tracker_get()
    print(t.peers)

    loop = asyncio.get_event_loop()
    coroutines = map(lambda p: tcp_handshake(p, loop, t), t.peers)
    loop.run_until_complete(asyncio.gather(*coroutines))

    loop.close()
