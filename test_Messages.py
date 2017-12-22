import unittest
from Messages import *


VALID_MESSAGES = {
    # (length, message): Message subclass instance
    (b"\x00\x00\x00\x00", b""): KeepAlive(),
    (b"\x00\x00\x00\x01", b"\x00"): Choke(),
    (b"\x00\x00\x00\x01", b"\x01"): Unchoke(),
    (b"\x00\x00\x00\x01", b"\x02"): Interested(),
    (b"\x00\x00\x00\x01", b"\x03"): NotInterested(),
    (b"\x00\x00\x00\x05", b"\x04\xff\xff\xff\xff"): Have(pow(2, 32)-1),
    (b"\x00\x00\x00\x05", b"\x05\x01\x02\x04\x08"): BitField({7, 14, 21, 28}, 32),
    (b"\x00\x00\x00\x0d", b"\x06\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x00\x03"): Request(1, 2, 3),
    (b"\x00\x00\x00\x0a", b"\x07\x00\x00\x00\x02\x00\x00\x00\x03\x78"): Piece(1, 2, 3, b"\x78"),
    (b"\x00\x00\x00\x0d", b"\x08\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x00\x03"): Cancel(1, 2, 3),
    (b"\x00\x00\x00\x05", b"\x09\x00\x00\x00\x2a"): Port(42),
}

VALID_HANDSHAKE = {
    b"\x13BitTorrent protocol\x00\x00\x00\x00\x00\x00\x00\x00\x92(b\x85\x04\xcc@\xef\xa5{"
    b"\xf3\x8e\x85\xc9\xe3\xbd,W+[-PY0001-000000000000":
    HandShake(b"\x92(b\x85\x04\xcc@\xef\xa5{\xf3\x8e\x85\xc9\xe3\xbd,W+[")
}


class TestMessageFromBytes(unittest.TestCase):
    def test_from_bytes_success(self):
        for key, value in VALID_MESSAGES.items():
            length, payload = key
            with self.subTest(case=payload, expected=value):
                m = Message.from_bytes(payload)
                self.assertEqual(m, value)

    def test_from_bytes_success_HandShake(self):
        for key, value in VALID_HANDSHAKE.items():
            with self.subTest(case=key, expected=value):
                m = HandShake.from_bytes(key)
                self.assertEqual(m, value)

    def test_from_bytes_failure(self):
        fail_cases = [
            (b"\x00\x00\x00\x01", b"\x99")
        ]
        for length, payload in fail_cases:
            with self.subTest(testCase=payload):
                with self.assertRaises(ValueError, msg="case '{0}'".format(payload)):
                    print(Message.from_bytes(payload))


class TestMessageToBytes(unittest.TestCase):
    def test_to_bytes_success(self):
        for key, value in VALID_MESSAGES.items():
            length, payload = key
            full_message = length + payload
            with self.subTest(case=value, expected=full_message):
                self.assertEqual(value.to_bytes(), full_message)

    def test_to_bytes_success_HandShake(self):
        for key, value in VALID_HANDSHAKE.items():
            with self.subTest(case=value, expected=key):
                self.assertEqual(value.to_bytes(), key)


class TestMessageClasses(unittest.TestCase):
    def test_HandShake(self):
        with self.subTest(case="String identifier of the protocol too large"):
            with self.assertRaises(ValueError):
                HandShake(b"." * 20, b"." * 999)

        with self.subTest(case="Invalid length for infohash"):
            with self.assertRaises(ValueError):
                HandShake(b"." * 999)


if __name__ == '__main__':
        unittest.main()
