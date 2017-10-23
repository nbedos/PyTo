from BEncoding import Bdecode, Bencode
import urllib.request
import urllib.parse
from hashlib import sha1

class peer:
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port
        self.choking = True
        self.choked = True


class metainfo:
    def __init__(self, torrent_file):
        with open(torrent_file, "rb") as f:
            m = Bdecode(f.read())

        try:
            self.announce = m[b'announce']
            self.info = m[b'info']
            self.info_hash = sha1(Bencode(self.info)).digest()
            return
        except KeyError:
            pass
        raise ValueError("Invalid metainfo")

    def tracker_get(self):
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

        url = "%s?%s" % (self.announce.decode(), urllib.parse.urlencode(h))
        print(url)
        with urllib.request.urlopen(url) as response:
            d = Bdecode(response.read())
            peers = list(map(_bytes_to_ipv4_port, _split(d[b"peers"], 6)))
            print(peers)


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
    ipv4 = "%i.%i.%i.%i" % (int.from_bytes(b[0:1], "big"),
                            int.from_bytes(b[1:2], "big"),
                            int.from_bytes(b[2:3], "big"),
                            int.from_bytes(b[3:4], "big"))
    port = int.from_bytes(b[4:6], "big")
    return (ipv4, port)


class torrent:
    def __init__(self, torrent_file):
        self.metainfo = metainfo(torrent_file)
        self.peers = {}


if __name__ == '__main__':
    m = metainfo("./data/torrent files/archlinux-2017.10.01-x86_64.iso.torrent")
    m.tracker_get()