import os
import unittest

from pyto.bencoding import bdecode, bencode


TEST_FILE_DIR = os.path.dirname(os.path.abspath(__file__))
# DATA_DIR is TEST_FILE_DIR/data 
DATA_DIR = os.path.join(TEST_FILE_DIR, 'data')

validBEncodings = {
    # INTEGERS
    b"i0e": 0,
    b"i24e": 24,
    b"i-24e": -24,
    b"i9999999999999999e": 9999999999999999,
    # STRINGS
    b"4:spam": b"spam",
    # Empty string
    b"0:": b"",
    # LISTS
    b"l4:spam4:spami42ee": [b"spam", b"spam", 42],
    # Empty list
    b"le": [],
    # List of a dictionary and a list
    b"ll4:spam4:spami42eed3:cow3:moo4:spam4:eggsee": [[b"spam", b"spam", 42], {b"cow": b"moo", b"spam": b"eggs"}],
    # DICTIONARIES
    b"d3:cow3:moo4:spam4:eggse": {b"cow": b"moo", b"spam": b"eggs"},
    # Dictionary of list and dictionary
    b"d4:spaml4:spam4:spami42ee4:spomd3:cow3:moo4:spam4:eggsee": {b"spam": [b"spam", b"spam", 42],
                                                                  b"spom": {b"cow": b"moo", b"spam": b"eggs"}},
    # Empty dictionary
    b"de": {},
    # Keys of a dictionary must be sorted (byte order, not lexicogaphical order)
    b"d1:ai2e1:bi1ee": {b'b': 1, b'a': 2}
}


class TestBdecode(unittest.TestCase):
    def test_Bdecode_success(self):
        for (key, value) in validBEncodings.items():
            with self.subTest(case=key, expected=value, result=bdecode(key)):
                self.assertEqual(bdecode(key), value)

    def test_Bdecode_failure(self):
        fail_cases = [
            # Invalid string lengths
            b"4:spa",
            b"2:spa"
            b"-1:x",
            b"-4:spam",
            b"0-4:spam",
            b"0:e",
            # Dictionary key must be a string
            b"di42e4:spame",
            # Dictionary with no terminating "e"
            b"d4:spami42e4:spomi43e",
            # Wrong key ordering
            b"d3:tow3:moo4:spam4:eggse",
            # Invalid integers
            b"i2Fe",
            b"ie",
            b"i42",
            b"i--23e",
            b"i1+1e",
            b"i1,2e",
            b"i1.2e",
            b"i1.0e",
            b"i1,0e",
            b"i-0e",
            b"i01e",
            # List with no terminating "e"
            b"li42ei43e"
        ]
        for testCase in fail_cases:
            with self.subTest(testCase=testCase):
                with self.assertRaises(ValueError, msg="case '{0}'".format(testCase)):
                    print(bdecode(testCase))


class TestBencode(unittest.TestCase):
    def test_Bencode_success(self):
        for (key, value) in validBEncodings.items():
            with self.subTest(case=value, expected=key, result=bencode(value)):
                self.assertEqual(bencode(value), key)

    def test_Bencode_failure(self):
        fail_cases = [
            # Number but not an integer
            1.0,
            # String instead of a bytestring
            "a",
            # Dictionary keys must be bytestrings
            {1: b"a", 2: b"b"},
            {"b": b"a", "a": b"b"}
        ]
        for testCase in fail_cases:
            with self.subTest(testCase=testCase):
                with self.assertRaises(ValueError, msg="case '{0}'".format(testCase)):
                    bencode(testCase)


class TestEndToEnd(unittest.TestCase):
    def test_bencode_bdecode(self):
        # Decode whole Torrent files
        torrent_dir = os.path.join(DATA_DIR, "torrent_files")
        for file in os.listdir(torrent_dir):
            filename = os.path.join(torrent_dir, os.fsdecode(file))
            with open(filename, "rb") as f:
                with self.subTest(filename=filename):
                    s = f.read()
                    self.assertEqual(s, bencode(bdecode(s)))


if __name__ == '__main__':
    unittest.main()
