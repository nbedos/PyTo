from BEncoding import Bdecode, Bencode
import urllib.request
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
            'peer_id': "ABCDEFGHIJKLMNOPQRST",
            #'ip':
            'port': 6881,
            'uploaded': 0,
            'download': self.info[b'length'],
            'left': self.info[b'length']
            #'event':
        }

        req = urllib.request.Request(url=self.announce.decode(), headers=h)
        with urllib.request.urlopen(req) as response:
            print(response.read().decode('utf8'))


class torrent:
    def __init__(self, torrent_file):
        self.metainfo = metainfo(torrent_file)
        self.peers = {}



