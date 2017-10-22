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
            print(response.read())


class torrent:
    def __init__(self, torrent_file):
        self.metainfo = metainfo(torrent_file)
        self.peers = {}


if __name__ == '__main__':
    m = metainfo("./data/torrent files/archlinux-2017.10.01-x86_64.iso.torrent")
    m.tracker_get()