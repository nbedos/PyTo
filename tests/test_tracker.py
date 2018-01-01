import asyncio
import unittest
import urllib.parse

from pyto.tracker import Tracker

ANNOUNCE = "www.example.com/announce"
INFO_HASH = b'.' * 20
PEER_ID = '.' * 20
PORT = 6881


async def _request_mock(url):
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


class TestTracker(unittest.TestCase):
    def test_events(self):
        """Call the methods of Tracker successively to check that the right events are sent"""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        tracker = Tracker(announce=ANNOUNCE,
                          info_hash=INFO_HASH,
                          peer_id=PEER_ID,
                          port=PORT)
        tracker._request = _request_mock

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


if __name__ == '__main__':
    unittest.main()