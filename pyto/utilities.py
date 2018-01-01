import os.path
import struct
from typing import List, Tuple


def split(l: List, n: int) -> List:
    """Split the list l in chunks of size n"""
    if n < 0:
        raise ValueError("n must be >= 0")
    i = 0
    chunks = []
    while l[i:i + n]:
        chunks.append(l[i:i + n])
        i = i + n
    return chunks


def decode_ipv4(buffer: bytes) -> Tuple[str, int]:
    try:
        ip_str, port = struct.unpack(">4sH", buffer)
        ip = ".".join([str(n) for n, in struct.iter_unpack(">B", ip_str)])
        return ip, port
    except struct.error:
        pass
    raise ValueError("Invalid (ip, port)")


def validate_structure(data, schema) -> bool:
    """Check if the structure of 'data' conforms to 'schema'

    'schema' is a (minimal) data structure such as for example:
        s = {'announce': 'text', 'length': 1}

    Dictionaries in 'data' may have keys not found in schema

    Restriction: Elements of lists are checked against the first element of the corresponding
    list in schema: this makes it impossible to validate lists containing different types"""
    if isinstance(data, dict) and isinstance(schema, dict):
        tests = [key in data and validate_structure(data[key], schema[key]) for key in schema]
        return all(tests)
    elif isinstance(data, list):
        tests = [validate_structure(value, schema[0]) for value in data]
        return all(tests)
    else:
        return isinstance(data, type(schema))


def sanitize(filename: str) -> str:
    """Remove potentially treacherous characters from a path name"""
    allowed_characters = {' ', '-', '[', ']', '}', '{', '_', '.'}
    return "".join([c for c in filename if c.isalnum() or c in allowed_characters]).rstrip()


def intersection(interval1: Tuple[int, int], interval2: Tuple[int, int]):
    """Return the intersection of two closed intervals as an interval

    If the two intervals do not overlap, return None"""
    (a, b), (c, d) = interval1, interval2
    assert (a <= b) and (c <= d)

    lower_bound = max(a, c)
    upper_bound = min(b, d)

    if lower_bound <= upper_bound:
        return lower_bound, upper_bound

    return None


def path_components(mypath: str) -> List[str]:
    """Return the list of components in mypath:
        _path_components("A/B/C/D") = ['A', 'B', 'C', 'D']
    """
    components = []
    head = mypath
    while True:
        head, tail = os.path.split(head)
        if tail:
            components.insert(0, tail)
        else:
            if head:
                components.insert(0, head)
            break

    return components
