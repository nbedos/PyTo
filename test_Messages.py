from unittest import TestCase
from Messages import *


validMessages = {
    b"\x00\x00\x00\x00": KeepAlive(),
    b"\x00\x00\x00\x01\x00": Choke(),
    b"\x00\x00\x00\x01\x01": Unchoke(),
    b"\x00\x00\x00\x01\x02": Interested(),
    b"\x00\x00\x00\x01\x03": NotInterested(),
    b"\x00\x00\x00\x05\x04\xff\xff\xff\xff": Have(pow(2, 32)-1),
    b"\x00\x00\x00\x05\x05\x01\x23\x45\x67": BitField(b"\x01\x23\x45\x67", 4),
    b"\x00\x00\x00\x0d\x06\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x00\x03": Request(1, 2, 3),
    b"\x00\x00\x00\x0a\x07\x00\x00\x00\x02\x00\x00\x00\x03\x78": Piece(1, 2, 3, b"\x78"),
    b"\x00\x00\x00\x0d\x08\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x00\x03": Cancel(1, 2, 3),
    b"\x00\x00\x00\x05\x09\x00\x00\x00\x2a": Port(42),
    b"\x13BitTorrent protocol\x00\x00\x00\x00\x00\x00\x00\x00\x92(b\x85\x04\xcc@\xef\xa5{"
    b"\xf3\x8e\x85\xc9\xe3\xbd,W+[-PY0001-000000000000": HandShake(b"\x92(b\x85\x04\xcc@\xef\xa5{"
                                                                   b"\xf3\x8e\x85\xc9\xe3\xbd,W+[")
}


class TestMessageFromBytes(TestCase):
    def test_from_bytes_success(self):
        for (key, value) in validMessages.items():
            with self.subTest(case=key, expected=value):
                m, _ = Message.from_bytes(key)
                self.assertEqual(m, value)

    def test_from_bytes_consecutive(self):
        pass

    def test_from_bytes_failure(self):
        fail_cases = [
            b"\x00\x00\x00\x01\x99"
        ]
        for testCase in fail_cases:
            with self.subTest(testCase=testCase):
                with self.assertRaises(ValueError, msg="case '{0}'".format(testCase)):
                    print(Message.from_bytes(testCase))


class TestMessageToBytes(TestCase):
    def test_to_bytes_success(self):
        for (key, value) in validMessages.items():
            with self.subTest(case=value, expected=key):
                self.assertEqual(value.to_bytes(), key)