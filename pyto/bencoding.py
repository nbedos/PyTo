""" Utility functions for translating Python objects to and from bencoded bytestrings.

Specification: https://wiki.theory.org/index.php/BitTorrentSpecification#Bencoding
"""


def bdecode(s: bytes):
    """Decode the bencoded value stored in the bytestring.

    ValueError is raised if the whole string is not a valid bencoded value"""
    if isinstance(s, bytes):
        b, remainder = _bdecode_partial(s)
        if not remainder:
            return b
        raise ValueError("Invalid Bencoded string (part of the string was not consumed)")

    raise ValueError("Invalid Bencoded string (must be bytestring)")


def _bdecode_partial(s: bytes):
    """Return the first Bencoded value read from the bytestring,
    and the remainder of the bytestring.

    ValueError is raised if the bytestring does not start with a valid bencoded value."""
    if len(s) < 2:
        raise ValueError("Invalid Bencoded string (minimal length: 2)")
    # Integer :
    #   - "i42e" --> 42
    if s[0:1] == b"i":
        try:
            number, remainder = s[1:].split(b"e", 1)
            # 1/ The first digit can't be zero unless the number is zero
            # 2/ "i-0e" is invalid
            if (s[1:2] != b"0" or int(number) == 0) and (s[1:2] != b"-" or int(number) < 0):
                return int(number), remainder
        except ValueError:
            pass
        raise ValueError("Invalid Bencoded string (ill-formed integer)")
    # List
    #   - "li42e4:spame" --> [42, "spam"]
    elif s[0:1] == b"l":
        remainder = s[1:]
        l = []
        # Loop until we've reached the end of the list
        while remainder[0:1] != b"e":
            # Read one Bencoded value from the string
            b, remainder = _bdecode_partial(remainder)
            l.append(b)
        return l, remainder[1:]
    # Dictionary
    #   - "d3:cow3:moo4:spam4:eggse" --> {"cow": "moo", "spam": "eggs"}
    elif s[0:1] == b"d":
        remainder = s[1:]
        d = {}
        lastkey = None
        while remainder[0:1] != b"e":
            key, remainder = _bdecode_partial(remainder)
            if (lastkey is not None) and (key <= lastkey):
                raise ValueError("Invalid Bencoded dictionary (keys must be sorted)")

            # Dictionary key must be a string
            if isinstance(key, bytes):
                value, remainder = _bdecode_partial(remainder)
                d[key] = value
            else:
                raise ValueError("Invalid Bencoded dictionary (keys must be strings)")

            lastkey = key
        return d, remainder[1:]
    # String
    #   - "4:spam" --> "spam"
    else:
        try:
            length, remainder = s.split(b":", 1)
            if len(remainder) >= int(length):
                return remainder[0:int(length)], remainder[int(length):]
        except (ValueError, IndexError):
            pass
        raise ValueError("Invalid Bencoded string")


def bencode(o) -> bytes:
    """Return the Bencoded representation of the object.

    Exception: ValueError is raised if the object is invalid"""
    if isinstance(o, bytes):
        return b"%i:%s" % (len(o), o)
    elif isinstance(o, dict):
        return b"d%se" % b"".join([_bencodeDictItem(k, v) for k, v in sorted(o.items())])
    elif isinstance(o, list):
        return b"l%se" % b"".join(map(bencode, o))
    elif isinstance(o, int):
        return b"i%ie" % o

    raise ValueError("Invalid object (object must be a bytestring, an integer, a list or a "
                     "dictionary)")


def _bencodeDictItem(key: bytes, value):
    if isinstance(key, bytes):
        return bencode(key) + bencode(value)
    raise ValueError("Invalid object (dictionary key must be a bytestring)")
