from struct import *

def Bdecode(s):
    """ Decode the Bencoded value stored in the bytestring"""
    if isinstance(s, bytes):
        b, remainder = BdecodePartial(s)
        if len(remainder) == 0:
            return b
        else:
            raise ValueError("Invalid Bencoded string (part of the string was not consumed)")

    raise ValueError("Invalid Bencoded string (must be bytestring)")


def BdecodePartial(s):
    """ Return the first Bencoded value read from the bytestring,
    and the remainder of the bytestring.

    Exception: ValueError if the string is invalid"""
    if len(s) < 2:
        raise ValueError("Invalid Bencoded string (minimal length: 2)")
    # Integer :
    #   - "i42e" --> 42
    #   -
    if s[0:1] == b"i":
        try:
            number, remainder = s[1:].split(b"e", 1)
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
            b, remainder = BdecodePartial(remainder)
            l.append(b)
        return l, remainder[1:]
    # Dictionary
    #   - "d3:cow3:moo4:spam4:eggse" --> {"cow": "moo", "spam": "eggs"}
    elif s[0:1] == b"d":
        remainder = s[1:]
        d = {}
        lastkey = None
        while remainder[0:1] != b"e":
            key, remainder = BdecodePartial(remainder)
            if lastkey != None and key <= lastkey:
                raise ValueError("Invalid Bencoded dictionary (keys must be sorted)")

            # Dictionary key must be a string
            if isinstance(key, bytes):
                value, remainder = BdecodePartial(remainder)
                d[key] = value
            else:
                raise ValueError("Invalid Bencoded dictionary (keys must be strings)")

            lastkey = key
        return d, remainder[1:]
    # String
    #   - "4:spam" --> "spam"
    else:
        try:
            length, remainder = s.split(b":",1)
            if len(remainder) >= int(length):
                return remainder[0:int(length)], remainder[int(length):]
        except (ValueError, IndexError):
            pass
        raise ValueError("Invalid Bencoded string")


def Bencode(o):
    """Return the Bencoded representation of the object.

    Exception: ValueError is raised if the object is invalid"""
    if isinstance(o, bytes):
        return b"%i:%s" % (len(o), o)
    elif isinstance(o, dict):
        return b"d%se" % b"".join([_BencodeDictItem(k, v) for k, v in  sorted(o.items())])
    elif isinstance(o, list):
        return b"l%se" % b"".join(map(Bencode, o))
    elif isinstance(o, int):
        return b"i%ie" % o
    else:
        raise ValueError("Invalid object (object must be a bytestring, an integer, a list or a dictionary)")


def _BencodeDictItem(key, value):
    if isinstance(key, bytes):
        return Bencode(key) + Bencode(value)
    raise ValueError("Invalid object (dictionary key must be a bytestring)")
