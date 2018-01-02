"""
Implementation of the BitTorrent Tracker protocol over HTTP

Specifications:
    - HTTP protocol: http://www.bittorrent.org/beps/bep_0003.html#trackers
    - Announce-list: http://bittorrent.org/beps/bep_0012.html
    - Compact list extension: http://www.bittorrent.org/beps/bep_0023.html
"""

import aiohttp
import logging
import urllib.parse
import random

from typing import Iterator, List, Tuple

from pyto.utilities import split, decode_ipv4
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

    def __init__(self, announce: List[List[str]], info_hash: bytes, peer_id: str, port: int):
        if not announce:
            raise ValueError("Empty announce list")
        self._announce = announce
        # Initial shuffle of each tier as mandated by BEP 12
        for tier in self._announce:
            if tier:
                random.SystemRandom().shuffle(tier)
        # Last tier from which we got a response to an announce request. This is the tier to which
        # 'completed' and 'stopped' event should be sent.
        self._last_tier = None
        self._event = None
        self._info_hash = info_hash
        self._peer_id = peer_id
        self._port = port
        self._logger = _TrackerAdapter(module_logger, {'info_hash': str(self._info_hash)})

    def _build_url(self, tracker: str, uploaded: int, downloaded: int, left: int) -> str:
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
        url = "{}?{}".format(tracker, urllib.parse.urlencode(h))
        return url

    # TODO: Will the tracker send a response to 'completed' or 'stopped' requests ?
    # TODO: Maybe catch the exception if b'peers' is not a key of the response ?
    # TODO: Validate the response with a schema
    async def _query_tracker(self, url: str) -> Iterator[Tuple[str, int]]:
        """Send the request to the tracker"""
        self._logger.debug("request: {}".format(url))
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as response:
                if response.status != 200:
                    raise ConnectionError
                d = bdecode(await response.read())
                return map(decode_ipv4, split(d[b'peers'], 6))

    async def _query_tier(self, tier: int, uploaded: int, downloaded: int, left: int) -> \
            Iterator[Tuple[str, int]]:
        """Attempt querying each tracker of the tier

        Raise ConnectionError if every request fails"""
        for tracker in self._announce[tier][:]:
            url = self._build_url(tracker, uploaded, downloaded, left)
            try:
                response = await self._query_tracker(url)
            except ConnectionError:
                # Failure: put the tracker at the end of the tier
                self._announce[tier].remove(tracker)
                self._announce[tier].append(tracker)
            else:
                # Success: put the tracker at the beginning of the tier
                self._announce[tier].remove(tracker)
                self._announce[tier].insert(0, tracker)
                self._last_tier = tier
                return response
        self._last_tier = None
        raise ConnectionError

    async def get_peers(self, uploaded: int, downloaded: int, left: int):
        """Send an announce request"""
        for event in {Tracker._EVENT_STARTED, Tracker._EVENT_EMPTY}:
            if event in Tracker._NEXT_EVENTS[self._event]:
                self._event = event
                break
        else:
            raise ValueError("Invalid query: 'stopped' event already sent to the tracker")

        for tier_number in range(len(self._announce)):
            try:
                return await self._query_tier(tier_number, uploaded, downloaded, left)
            except ConnectionError:
                pass
        raise ConnectionError

    async def completed(self, uploaded: int, downloaded: int, left: int=0):
        if Tracker._EVENT_COMPLETED in Tracker._NEXT_EVENTS[self._event]:
            self._event = Tracker._EVENT_COMPLETED
        else:
            raise ValueError("Invalid query: 'started' event never sent to the tracker")

        response = await self._query_tier(self._last_tier, uploaded, downloaded, left)
        return response

    async def stopped(self, uploaded: int, downloaded: int, left: int):
        if Tracker._EVENT_STOPPED in Tracker._NEXT_EVENTS[self._event]:
            self._event = Tracker._EVENT_STOPPED
        else:
            raise ValueError("Invalid query: 'started' event never sent or 'stopped' event "
                             "already sent")

        response = await self._query_tier(self._last_tier, uploaded, downloaded, left)
        return response

