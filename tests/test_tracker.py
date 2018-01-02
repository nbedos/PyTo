import asyncio
import unittest
import urllib.parse

from pyto.tracker import Tracker

ANNOUNCE = [["www.example.com/announce"]]
INFO_HASH = b'.' * 20
PEER_ID = '.' * 20
PORT = 6881


async def _query_tracker_mock(url):
    """Return a dictionary made of the parameters of the request

    The return value for:
        "www.example.com/announce?key1=value1,value2&key=value3"
    would be:
        {
            key1: [value1, value2],
            key2: [value3]
        }
    """
    r = urllib.parse.urlparse(url)
    return urllib.parse.parse_qs(r.query)


async def _query_tracker_mock_fail_url(url):
    """Raise Connection error if the url contain 'fail', return a list of (ip, port) otherwise"""
    if 'fail' in url:
        raise ConnectionError
    return url


class TestTracker(unittest.TestCase):
    def test_events(self):
        """Call the methods of Tracker successively to check that the right events are sent"""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        tracker = Tracker(announce=ANNOUNCE,
                          info_hash=INFO_HASH,
                          peer_id=PEER_ID,
                          port=PORT)
        tracker._query_tracker = _query_tracker_mock

        with self.subTest(case="First call: 'started' event"):
            d = loop.run_until_complete(tracker.get_peers(0, 0, 0))
            self.assertEqual(d['event'], ['started'])

        with self.subTest(case="Second call: 'empty' event or no event at all"):
            d = loop.run_until_complete(tracker.get_peers(0, 0, 0))
            self.assertTrue('event' not in d or d['event'] == [''])

        with self.subTest(case="Third call: 'empty' event again"):
            # That's exactly the same call as before, it should send exactly the same request
            d_last = d
            d = loop.run_until_complete(tracker.get_peers(0, 0, 0))
            self.assertEqual(d, d_last)

        with self.subTest(case="Fourth call: 'completed' event"):
            d = loop.run_until_complete(tracker.completed(0, 0, 0))
            self.assertTrue(d['event'], ['completed'])

        with self.subTest(case="Fifth call: 'stopped' event"):
            d = loop.run_until_complete(tracker.stopped(0, 0, 0))
            self.assertTrue(d['event'], ['stopped'])

        loop.stop()
        loop.close()

    def test_tiers_requested(self):
        """
        Check that the trackers are queried in the following order (BEP 12):
                1/ Trackers in tier 1 (stop at the first response)
                2/ If every request to tier 1 trackers failed, try trackers in tier 2
                3/ Then try trackers in tier 3
                4/ ...
        """
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        with self.subTest(case="Only good tracker in tier 1"):
            announce = [['www.tier0.com/fail', 'www.tier0.com/fail', 'www.tier0.com/fail'],
                        ['www.tier1.com/fail', 'www.tier1.com/success', 'www.tier1.com/fail'],
                        ['www.tier2.com/fail', 'www.tier2.com/fail', 'www.tier2.com/fail']]
            tracker = Tracker(announce=announce,
                              info_hash=INFO_HASH,
                              peer_id=PEER_ID,
                              port=PORT)
            tracker._query_tracker = _query_tracker_mock_fail_url
            url = loop.run_until_complete(tracker.get_peers(0, 0, 0))
            self.assertIn('tier1', url)

        with self.subTest(case="No good tracker: raise ConnectionError"):
            announce = [['www.tier0.com/fail', 'www.tier0.com/fail', 'www.tier0.com/fail'],
                        ['www.tier1.com/fail', 'www.tier1.com/fail', 'www.tier1.com/fail'],
                        ['www.tier2.com/fail', 'www.tier2.com/fail', 'www.tier2.com/fail']]
            tracker = Tracker(announce=announce,
                              info_hash=INFO_HASH,
                              peer_id=PEER_ID,
                              port=PORT)
            tracker._query_tracker = _query_tracker_mock_fail_url
            with self.assertRaises(ConnectionError):
                loop.run_until_complete(tracker.get_peers(0, 0, 0))

        with self.subTest(case="'completed' and 'stopped' events sent to the last tier"):
            """'completed' and 'stopped' must be sent to the tier who last answered to an 
            announce request"""
            announce = [['www.tier0.com/fail', 'www.tier0.com/fail', 'www.tier0.com/fail'],
                        ['www.tier1.com/fail', 'www.tier1.com/success', 'www.tier1.com/fail'],
                        ['www.tier2.com/fail', 'www.tier2.com/success', 'www.tier2.com/fail']]
            tracker = Tracker(announce=announce,
                              info_hash=INFO_HASH,
                              peer_id=PEER_ID,
                              port=PORT)
            tracker._query_tracker = _query_tracker_mock_fail_url
            # First announce request should succeed with tier 1
            url = loop.run_until_complete(tracker.get_peers(0, 0, 0))
            self.assertIn('tier1', url)
            # Force failure of tier 1 on next announce request, request should succeed with tier 2
            tracker._announce[1] = ['www.example.com/fail']
            url = loop.run_until_complete(tracker.get_peers(0, 0, 0))
            self.assertIn('tier2', url)
            # 'completed' event should be sent to tier2
            url = loop.run_until_complete(tracker.completed(0, 0, 0))
            self.assertIn('tier2', url)
            # 'stopped' event should be sent to tier2
            url = loop.run_until_complete(tracker.stopped(0, 0, 0))
            self.assertIn('tier2', url)

        loop.stop()
        loop.close()


if __name__ == '__main__':
    unittest.main()
