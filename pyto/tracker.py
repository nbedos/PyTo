"""
Implementation of the BitTorrent Tracker protocol over HTTP

Specifications:
    - HTTP protocol: http://www.bittorrent.org/beps/bep_0003.html#trackers
    - Compact list extension: http://www.bittorrent.org/beps/bep_0023.html
"""

import aiohttp
import logging
import struct
import urllib.parse

from typing import List, Tuple

from pyto.bencoding import bdecode

module_logger = logging.getLogger(__name__)


class _TrackerAdapter(logging.LoggerAdapter):
    """Add the infohash to _logger messages"""
    def process(self, msg, kwargs):
        return '{:>20} {}'.format(self.extra['info_hash'], msg), kwargs


class Tracker(object):
    _EVENT_STARTED = 'started'
    _EVENT_COMPLETED = 'completed'
    _EVENT_EMPTY = ''
    _EVENT_STOPPED = 'stopped'

    _NEXT_EVENTS = {
        None: {_EVENT_STARTED},
        _EVENT_STARTED: {_EVENT_EMPTY, _EVENT_COMPLETED, _EVENT_STOPPED},
        _EVENT_EMPTY: {_EVENT_EMPTY, _EVENT_COMPLETED, _EVENT_STOPPED},
        _EVENT_COMPLETED: {_EVENT_STOPPED},
        _EVENT_STOPPED: {}
    }

    def __init__(self, announce: str, info_hash: bytes, peer_id: str, port: int):
        self._announce = announce
        self._info_hash = info_hash
        self._peer_id = peer_id
        self._port = port
        self._event = None
        self._logger = _TrackerAdapter(module_logger, {'info_hash': str(self._info_hash)})

    def _build_url(self, uploaded: int, downloaded: int, left: int) -> str:
        h = {
            'info_hash': self._info_hash,
            'peer_id': self._peer_id,
            'port': self._port,
            'uploaded': uploaded,
            'downloaded': downloaded,
            'left': left,
            'event': self._event,
            'compact': 1
        }
        url = "{}?{}".format(self._announce, urllib.parse.urlencode(h))
        return url

    # TODO: Will the tracker send a response to 'completed' or 'stopped' requests ?
    # TODO: Maybe catch the exception if b'peers' is not a key of the response ?
    async def _request(self, url: str):
        """Send the request to the tracker"""
        self._logger.debug("request: {}".format(url))
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as response:
                print(response.status)
                d = bdecode(await response.read())
                return map(_decode_ipv4, _split(d[b'peers'], 6))

    async def get_peers(self, uploaded: int, downloaded: int, left: int):
        for event in {Tracker._EVENT_STARTED, Tracker._EVENT_EMPTY}:
            if event in Tracker._NEXT_EVENTS[self._event]:
                self._event = event
                break
        else:
            raise ValueError("Invalid query: 'stopped' event already sent to the tracker")

        url = self._build_url(uploaded, downloaded, left)
        response = await self._request(url)
        return response

    async def completed(self, uploaded: int, downloaded: int, left: int=0):
        if Tracker._EVENT_COMPLETED in Tracker._NEXT_EVENTS[self._event]:
            self._event = Tracker._EVENT_COMPLETED
        else:
            raise ValueError("Invalid query: 'started' event never sent to the tracker")

        url = self._build_url(uploaded, downloaded, left)
        response = await self._request(url)
        return response

    async def stopped(self, uploaded: int, downloaded: int, left: int):
        if Tracker._EVENT_STOPPED in Tracker._NEXT_EVENTS[self._event]:
            self._event = Tracker._EVENT_STOPPED
        else:
            raise ValueError("Invalid query: 'started' event never sent or 'stopped' event "
                             "already sent")

        url = self._build_url(uploaded, downloaded, left)
        response = await self._request(url)
        return response


def _split(l: List, n: int) -> List:
    """Split the list l in chunks of size n"""
    if n < 0:
        raise ValueError("n must be >= 0")
    i = 0
    chunks = []
    while l[i:i + n]:
        chunks.append(l[i:i + n])
        i = i + n
    return chunks


def _decode_ipv4(buffer: bytes) -> Tuple[str, int]:
    try:
        ip_str, port = struct.unpack(">4sH", buffer)
        ip = ".".join([str(n) for n, in struct.iter_unpack(">B", ip_str)])
        return ip, port
    except struct.error:
        pass
    raise ValueError("Invalid (ip, port)")

