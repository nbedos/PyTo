"""Classes representing messages defined by the Peer Wire Protocol

Each message type has its own subclass and its own methods for converting to and from
bytestrings.

Subclasses have two methods for decoding messages:
    - from_bytes() decodes the full message. Bytes not consumed are returned along with the message
    - from_payload() decodes only the payload, the length prefix and message id must be checked
    beforehand. The bytestring must be exactly the right size or the methods raises an exception.

Specification: https://wiki.theory.org/index.php/BitTorrentSpecification#Peer_wire_protocol_.28TCP.29
"""
# TODO: Implement @properties for checking attributes in constructors

from struct import pack, unpack, error as struct_error
from typing import Set

# HandShake - String identifier of the protocol for BitTorrent V1
HANDSHAKE_PSTR_V1 = b"BitTorrent protocol"
LENGTH_PREFIX = 4


class Message(object):
    """Represent a generic message as defined by the Peer Wire Protocol."""
    def __init__(self, length: int):
        self.length = length

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return self.__dict__ == other.__dict__
        else:
            return False

    def __repr__(self):
        return "{0}: {1}".format(self.__class__, sorted(self.__dict__.items()))

    def to_bytes(self) -> bytes:
        try:
            return pack(">IB", self.length, type(self).message_id)
        except AttributeError:
            return pack(">I", self.length)

    @classmethod
    def from_payload(cls, payload: bytes):
        """Generic method for messages with no payload"""
        assert(not payload)
        return cls()

    @classmethod
    def from_bytes(cls, buffer: bytes):
        """Read a bytestring and return the corresponding Message subclass instance

        Raise ValueError if the bytestring is not a valid Message.

        This method allows decoding for any subclass of Message that has a message_id class
        attribute (for now this is every message except HandShake)."""

        # Special case for KeepAlive which length is 0 (no message id or payload)
        if buffer == b"":
            return KeepAlive()

        buffer_id, buffer_payload = buffer[:1], buffer[1:]
        # Extract the message id
        try:
            message_id, = unpack(">B", buffer_id)
        except struct_error:
            raise ValueError("Invalid message_id")

        # Choose the right decoding function for the payload based on the message_id
        try:
            decode = DECODING_FUNCTIONS[message_id]
        except KeyError:
            raise ValueError("Invalid message_id")

        return decode(buffer_payload)


class HandShake(Message):
    """Handshake = <pstrlen><pstr><reserved><info_hash><peer_id>
        - pstrlen = length of pstr (1 byte)
        - pstr = string identifier of the protocol: "BitTorrent protocol" (19 bytes)
        - reserved = 8 reserved bytes indicating extensions to the protocol (8 bytes)
        - info_hash = hash of the value of the 'info' key of the torrent file (20 bytes)
        - peer_id = unique identifier of the Peer (20 bytes)

    Total length of the message = 49 + len(pstr) = 68 for BitTorrent v1"""
    length_v1 = 49 + len(HANDSHAKE_PSTR_V1)

    def __init__(self,
                 info_hash: bytes,
                 pstr: bytes = HANDSHAKE_PSTR_V1,
                 reserved: bytes = b"\x00" * 8,
                 peer_id: bytes = b"-PY0001-000000000000"):
        super(HandShake, self).__init__(49 + len(pstr))
        # pstrlen is only 1 byte long so pstr can not exceed 255 bytes
        if len(pstr) > 255:
            raise ValueError("string identifier of the protocol too long (max: 255 bytes)")
        self.pstr = pstr
        self.reserved = reserved
        if len(info_hash) != 20:
            raise ValueError("Invalid length for info_hash")
        self.info_hash = info_hash
        self.peer_id = peer_id

    def to_bytes(self):
        """Return the bytestring representation of the HandShake message"""
        try:
            return pack(">B{}s8s20s20s".format(len(self.pstr)),
                        len(self.pstr),
                        self.pstr,
                        self.reserved,
                        self.info_hash,
                        self.peer_id)
        except struct_error:
            raise ValueError("Invalid values for encoding the HandShake instance")

    @classmethod
    def from_bytes(cls, buffer: bytes):
        """Read a bytestring and return a HandShake object"""
        try:
            pstrlen, = unpack(">B", buffer[:1])
            pstr, reserved, info_hash, peer_id = unpack(">{}s8s20s20s".format(pstrlen), buffer[1:])
        except struct_error:
            raise ValueError("Invalid binary format for HandShake message")

        if pstr != HANDSHAKE_PSTR_V1:
            raise ValueError("Invalid string identifier of the protocol")

        return HandShake(info_hash, pstr, reserved, peer_id)


class KeepAlive(Message):
    """KEEP_ALIVE = <length>
        - length = 0 (4 bytes)"""
    def __init__(self):
        super(KeepAlive, self).__init__(0)


class Choke(Message):
    """CHOKE = <length><message id>
        - length = 1 (4 bytes)
        - message id = 0 (1 byte)"""
    message_id = 0
    chokes_me = True

    def __init__(self):
        super(Choke, self).__init__(1)


class Unchoke(Message):
    """UNCHOKE = <length><message id>
        - length = 1 (4 bytes)
        - message id = 1 (1 byte)"""
    message_id = 1
    chokes_me = False

    def __init__(self):
        super(Unchoke, self).__init__(1)


class Interested(Message):
    """INTERESTED = <length><message id>
        - length = 1 (4 bytes)
        - message id = 2 (1 byte)"""
    message_id = 2
    interested = True

    def __init__(self):
        super(Interested, self).__init__(1)


class NotInterested(Message):
    """NOT INTERESTED = <length><message id>
        - length = 1 (4 bytes)
        - message id = 3 (1 byte)"""
    message_id = 3
    interested = False

    def __init__(self):
        super(NotInterested, self).__init__(1)


class Have(Message):
    """ HAVE = <length><message id><piece index>
        - length = 5 (4 bytes)
        - message id = 4 (1 byte)
        - piece index = zero based index of the piece (4 bytes)"""
    message_id = 4

    def __init__(self, piece_index: int):
        super(Have, self).__init__(5)
        self.piece_index = piece_index

    def to_bytes(self) -> bytes:
        try:
            return pack(">IBI",
                        self.length,
                        self.message_id,
                        self.piece_index)
        except struct_error:
            pass
        raise ValueError("Invalid values for encoding the Have instance")

    @classmethod
    def from_payload(cls, payload: bytes):
        try:
            piece_index, = unpack(">I", payload)
            return cls(piece_index)
        except struct_error:
            raise ValueError("Invalid binary format for Have message")


class BitField(Message):
    """BITFIELD = <length><message id><bitfield>
        - length = 1 + bitfield_size (4 bytes)
        - message id = 5 (1 byte)
        - bitfield = bitfield representing downloaded pieces (bitfield_size bytes)"""
    message_id = 5

    def __init__(self, pieces: Set[int], nbr_pieces: int):
        q, r = divmod(nbr_pieces, 8)
        nbr_bytes = q + int(bool(r))
        super(BitField, self).__init__(1 + nbr_bytes)
        self.pieces = pieces
        self.nbr_pieces = nbr_pieces

    def to_bytes(self) -> bytes:
        bitfield = bytearray(b"\x00" * (self.length - 1))
        for piece_index in self.pieces:
            q, r = divmod(piece_index, 8)
            bitfield[q] += 128 >> r
        try:
            return pack(">IB{}s".format(len(bitfield)),
                        self.length,
                        self.message_id,
                        bitfield)
        except struct_error:
            raise ValueError("Invalid values for encoding the BitField instance")

    @classmethod
    def from_payload(cls, payload: bytes):
        pieces = set([])
        for index, byte in enumerate(payload):
            for order in range(7, -1, -1):
                if (byte >> order) & 1:
                    pieces.add(index * 8 + 7 - order)

        return BitField(pieces, len(payload) * 8)


class Request(Message):
    """REQUEST = <length><message id><piece index><block offset><block length>
        - length = 13 (4 bytes)
        - message id = 6 (1 byte)
        - piece index = zero based piece index (4 bytes)
        - block offset = zero based of the requested block (4 bytes)
        - block length = length of the requested block (4 bytes)"""
    message_id = 6

    def __init__(self, piece_index: int, block_offset: int, block_length: int):
        super(Request, self).__init__(13)
        self.piece_index = piece_index
        self.block_offset = block_offset
        self.block_length = block_length

    def to_bytes(self) -> bytes:
        try:
            return pack(">IBIII",
                        self.length,
                        self.message_id,
                        self.piece_index,
                        self.block_offset,
                        self.block_length)
        except struct_error:
            raise ValueError("Invalid values for encoding the Request instance")

    @classmethod
    def from_payload(cls, payload: bytes):
        try:
            piece_index, block_offset, block_length = unpack(">III", payload)
            return Request(piece_index, block_offset, block_length)
        except struct_error:
            raise ValueError("Invalid binary format for Request message")


class Piece(Message):
    """PIECE = <length><message id><piece index><block offset><block>
        - length = 9 + block length (4 bytes)
        - message id = 7 (1 byte)
        - piece index =  zero based piece index (4 bytes)
        - block offset = zero based of the requested block (4 bytes)
        - block = block as a bytestring or bytearray (block_length bytes)"""
    message_id = 7

    def __init__(self, block_length: int, piece_index: int, block_offset: int, block: bytes):
        super(Piece, self).__init__(9+block_length)
        self.block_length = block_length
        self.piece_index = piece_index
        self.block_offset = block_offset
        self.block = block

    def __repr__(self):
        attributes = self.__dict__.copy()
        attributes["block"] = attributes["block"][0:20] + b" (truncated)"
        return "{0}: {1}".format(self.__class__, sorted(attributes.items()))

    def to_bytes(self) -> bytes:
        try:
            return pack(">IBII{}s".format(self.block_length),
                        self.length,
                        self.message_id,
                        self.piece_index,
                        self.block_offset,
                        self.block)
        except struct_error:
            raise ValueError("Invalid values for encoding the Piece instance")

    @classmethod
    def from_payload(cls, payload: bytes):
        block_length = len(payload) - 8
        try:
            piece_index, block_offset, block = unpack(">II{}s".format(block_length), payload)
            return Piece(block_length, piece_index, block_offset, block)
        except struct_error:
            raise ValueError("Invalid binary format for Piece message")


class Cancel(Message):
    """CANCEL = <length><message id><piece index><block offset><block length>
        - length = 13 (4 bytes)
        - message id = 8 (1 byte)
        - piece index = zero based piece index (4 bytes)
        - block offset = zero based of the requested block (4 bytes)
        - block length = length of the requested block (4 bytes)"""
    message_id = 8

    def __init__(self, piece_index: int, block_offset: int, block_length: int):
        super(Cancel, self).__init__(13)
        self.piece_index = piece_index
        self.block_offset = block_offset
        self.block_length = block_length

    def to_bytes(self) -> bytes:
        try:
            return pack(">IBIII",
                        self.length,
                        self.message_id,
                        self.piece_index,
                        self.block_offset,
                        self.block_length)
        except struct_error:
            raise ValueError("Invalid values for encoding the Cancel instance")

    @classmethod
    def from_payload(cls, payload: bytes):
        try:
            piece_index, block_offset, block_length = unpack(">III", payload)
            return Cancel(piece_index, block_offset, block_length)
        except struct_error:
            raise ValueError("Invalid binary format for Cancel message")


class Port(Message):
    """PORT = <length><message id><port number>
        - length = 5 (4 bytes)
        - message id = 9 (1 byte)
        - port number = listen_port (4 bytes)"""
    message_id = 9

    def __init__(self, listen_port: int):
        super(Port, self).__init__(5)
        self.listen_port = listen_port

    def to_bytes(self) -> bytes:
        try:
            return pack(">IBI",
                        self.length,
                        self.message_id,
                        self.listen_port)
        except struct_error:
            raise ValueError("Invalid values for encoding the Port instance")

    @classmethod
    def from_payload(cls, payload: bytes):
        try:
            listen_port, = unpack(">I", payload)
            return Port(listen_port)
        except struct_error:
            raise ValueError("Invalid binary format for Port message")


# TODO: Add a metaclass to Message to update the following dictionary when a class is created
DECODING_FUNCTIONS = {cls.message_id: cls.from_payload for cls in
                      Message.__subclasses__() if
                      hasattr(cls, "message_id")}


def decode_length(b: bytes) -> int:
    try:
        length, = unpack(">I", b)
    except struct_error:
        raise ValueError("Invalid length prefix")
    return length


if __name__ == "__main__":
    pass
