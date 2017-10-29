from unittest import TestCase
from Messages import *


validMessages = {
    b"\x00\x00\x00\x00": KeepAlive(),
    b"\x00\x00\x00\x01\x00": Choke(),
    b"\x00\x00\x00\x01\x01": Unchoke(),
    b"\x00\x00\x00\x01\x02": Interested(),
    b"\x00\x00\x00\x01\x03": NotInterested(),
    b"\x00\x00\x00\x05\x04\xff\xff\xff\xff": Have(pow(2, 32)-1)
}


class TestMessageFromBytes(TestCase):
    def test_from_bytes_success(self):
        for (key, value) in validMessages.items():
            with self.subTest(case=key, expected=value):
                m, _ = Message.from_bytes(key)
                self.assertEqual(m, value)

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


"""   def test_to_bytes_failure(self):
        fail_cases = [
            1.0,
            # String instead of a bytestring
            "a",
            # Dictionary keys must be strings
            {1: b"a", 2: b"b"},
        ]
        for testCase in fail_cases:
            with self.subTest(testCase=testCase):
                with self.assertRaises(ValueError, msg="case '{0}'".format(testCase)):
                    print(bencode(testCase))"""
