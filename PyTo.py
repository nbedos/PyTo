from BEncoding import Bdecode, Bencode
import urllib.request
import urllib.parse
from hashlib import sha1
import asyncio

from struct import *

class peer:
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port
        self.choking = True
        self.choked = True
    def __repr__(self):
        return "peer({}:{}, choking={}, choked={})".format(self.ip,
                                                           self.port,
                                                           self.choking,
                                                           self.choked)

    def keep_alive(self):
        return b"\x00\x00\x00\x00"

    def choke(self):
        return b"\x00\x00\x00\x01\x00"

    def unchoke(self):
        return b"\x00\x00\x00\x01\x01"

    def interested(self):
        return b"\x00\x00\x00\x01\x02"

    def not_interested(self):
        return b"\x00\x00\x00\x01\x03"

    def have(self, piece_index):
        return pack(">ii", 5, piece_index)

    def bitfield(self, m):
        return None






def handshake(info_hash):
    # Length of the string identifier of the protocol (1 byte)
    pstrlen = b"\x13"
    # String identifier of the protocol
    pstr = b"BitTorrent protocol"
    # 8 reserved bytes
    reserved = b"\x00\x00\x00\x00\x00\x00\x00\x00"
    # Unique ID for the client
    # TODO: randomize
    peer_id = b"-PY0001-000000000000"
    return b"".join([pstrlen,
                     pstr,
                     reserved,
                     info_hash,
                     peer_id])


class metainfo:
    def __init__(self, torrent_file):
        # TODO: Check if all necessary keys are in the info dictionary
        with open(torrent_file, "rb") as f:
            m = Bdecode(f.read())

        try:
            self.announce = m[b'announce']
            self.info = m[b'info']
            # Binary form of the SHA1 hash
            self.info_hash = sha1(Bencode(self.info)).digest()
            return
        except KeyError:
            pass
        raise ValueError("Invalid metainfo")

    def __repr__(self):
        return "metainfo:\n\tannounce: {}".format(self.announce.decode())

def _split(l, n):
    """Split the list l in chunks of size n"""
    if n < 0:
        raise ValueError("n must be >= 0")
    i = 0
    L = []
    while l[i:i+n]:
        L.append(l[i:i+n])
        i = i + n
    return L


def _bytes_to_ipv4_port(b):
    #print(b)
    ipv4 = "{}.{}.{}.{}".format(int.from_bytes(b[0:1], "big"),
                                int.from_bytes(b[1:2], "big"),
                                int.from_bytes(b[2:3], "big"),
                                int.from_bytes(b[3:4], "big"))
    port = int.from_bytes(b[4:6], "big")
    #print("{}:{}".format(ipv4, port))
    return peer(ipv4, port)


class torrent:
    def __init__(self, torrent_file):
        self.metainfo = metainfo(torrent_file)
        self.peers = []

        self.piece_length = self.metainfo.info[b"piece length"]
        self.length = self.metainfo.info[b"length"]
        q, r = divmod(self.length, self.piece_length)
        self.nbr_pieces = q + int(bool(r))

        q, r = divmod(self.nbr_pieces, 8)
        bitfield_size = q + int(bool(r))
        self.bitfield = bytearray(b"\x00" * bitfield_size)

    def tracker_get(self):
        """Send an announce query to the tracker"""
        m = self.metainfo
        h = {
            'info_hash': m.info_hash,
            'peer_id': "-HT00000000000000000",
            'port': 6881,
            'uploaded': 0,
            'downloaded': 0,
            'left': m.info[b'length'],
            'event': "started",
            'compact': 1
        }

        url = "{}?{}".format(m.announce.decode(), urllib.parse.urlencode(h))
        print(url)
        with urllib.request.urlopen(url) as response:
            d = Bdecode(response.read())
            self.peers = list(map(_bytes_to_ipv4_port, _split(d[b"peers"], 6)))


async def tcp_handshake(peer, loop):
    header = b"[%r:%d] " % (peer.ip, peer.port)
    print(header + b"Connecting...")
    try:
        reader, writer = await asyncio.open_connection(peer.ip, peer.port, loop=loop)
        print(header + b"Connected!")

        message = handshake(t.metainfo.info_hash)
        print(header + b"Send: " + message)
        writer.write(message)

        data = await reader.read(100)
    except (ConnectionRefusedError,
            ConnectionAbortedError,
            ConnectionError,
            ConnectionResetError,
            TimeoutError,
            OSError) as e:
        print("[{}:{}] Exception: {}".format(peer.ip, peer.port, e))
        return
    print(header + b"Received: " + data)

    writer.close()
    print(header + b"Closed socket")


if __name__ == '__main__':
    # t = torrent("./data/torrent files/archlinux-2017.10.01-x86_64.iso.torrent")
    t = torrent("./data/torrent files/archlinux-2017.10.01-x86_64.iso.torrent")
    print(t.metainfo)
    t.tracker_get()
    print(t.peers)

    loop = asyncio.get_event_loop()
    coroutines = map(lambda p: tcp_handshake(p, loop), t.peers)
    loop.run_until_complete(asyncio.gather(*coroutines))

    loop.close()



