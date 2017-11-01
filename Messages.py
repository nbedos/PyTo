from struct import pack, unpack
from typing import Union

class Message:
    def __init__(self, length: int, message_id: Union[int, None]=None):
        self.length = length
        if message_id is not None:
            self.message_id = message_id

    #TODO: Check this - https://stackoverflow.com/questions/390250/elegant-ways-to-support-equivalence-equality-in-python-classes
    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return self.__dict__ == other.__dict__
        return NotImplemented

    def __ne__(self, other):
        if isinstance(other, self.__class__):
            return not self.__eq__(other)
        return NotImplemented

    #def __hash__(self):
    #    """Override the default hash behavior (that returns the id or the object)"""
    #    return hash(tuple(sorted(self.__dict__.items())))

    def __repr__(self):
        return "{0}: {1}".format(self.__class__, sorted(self.__dict__.items()))

    def to_bytes(self) -> bytes:
        try:
            return pack(">IB", self.length, self.message_id)
        except AttributeError:
            return pack(">I", self.length)

    @classmethod
    def from_bytes(cls, buffer: bytes):
        """Read a bytestring and return a tuple containing the corresponding Subclass instance along
        with the rest of the bytestring.

        If the string stored in the buffer is incomplete, (None, buffer) is returned.
        If the string can't be translated to a valid Message, ValueError is raised."""

        # First, attempt reading the "length" prefix of the message which is LENGTH_SIZE bytes long
        LENGTH_SIZE = 4
        buffer_length = len(buffer)
        if LENGTH_SIZE > buffer_length:
            return None, buffer
        message_length, = unpack(">I", buffer[0:LENGTH_SIZE])
        if message_length == 0:
            return KeepAlive(), buffer[LENGTH_SIZE:]

        total_message_length = LENGTH_SIZE + message_length
        # Second, check if we've got the full message in the buffer
        if buffer_length < total_message_length:
            return None, buffer

        # At this point message_length is at least 1 so we can read the message_id from the buffer
        message_id, = unpack(">B", buffer[LENGTH_SIZE:LENGTH_SIZE+1])

        message_buffer, rest = buffer[:total_message_length], buffer[total_message_length:]

        # Map message ids to Message decoding methods
        decoding_functions = {
            0: Choke.from_bytes,
            1: Unchoke.from_bytes,
            2: Interested.from_bytes,
            3: NotInterested.from_bytes,
            4: Have.from_bytes,
            5: BitField.from_bytes,
            6: Request.from_bytes,
            7: Piece.from_bytes,
            8: Cancel.from_bytes,
            9: Port.from_bytes
        }
        
        try:
            return decoding_functions[message_id](message_buffer), rest
        except KeyError:
            pass
        
        raise ValueError("Invalid binary format for Message")


class KeepAlive(Message):
    """KEEP_ALIVE = <length>
        - length = 0 (4 bytes)"""
    def __init__(self):
        super(KeepAlive, self).__init__(0)


class Choke(Message):
    """CHOKE = <length><message id>
        - length = 1 (4 bytes)
        - message id = 0 (1 byte)"""
    def __init__(self):
        super(Choke, self).__init__(1, 0)

    @classmethod
    def from_bytes(cls, buffer: bytes):
        length, message_id = unpack(">IB", buffer)
        if message_id == 0 and length == 1:
            return cls()
        raise ValueError("Invalid binary format for Choke message")


class Unchoke(Message):
    """UNCHOKE = <length><message id>
        - length = 1 (4 bytes)
        - message id = 1 (1 byte)"""
    def __init__(self):
        super(Unchoke, self).__init__(1, 1)

    @classmethod
    def from_bytes(cls, buffer: bytes):
        length, message_id = unpack(">IB", buffer)
        if message_id == 1 and length == 1:
            return cls()
        raise ValueError("Invalid binary format for UnChoke message")


class Interested(Message):
    """INTERESTED = <length><message id>
        - length = 1 (4 bytes)
        - message id = 2 (1 byte)"""
    def __init__(self):
        super(Interested, self).__init__(1, 2)

    @classmethod
    def from_bytes(cls, buffer: bytes):
        length, message_id = unpack(">IB", buffer)
        if message_id == 2 and length == 1:
            return cls()
        raise ValueError("Invalid binary format for Interested message")


class NotInterested(Message):
    """NOT INTERESTED = <length><message id>
        - length = 1 (4 bytes)
        - message id = 3 (1 byte)"""
    def __init__(self):
        super(NotInterested, self).__init__(1, 3)

    @classmethod
    def from_bytes(cls, buffer: bytes):
        length, message_id = unpack(">IB", buffer)
        if message_id == 3 and length == 1:
            return cls()
        raise ValueError("Invalid binary format for NotInterested message")


class Have(Message):
    """ HAVE = <length><message id><piece index>
        - length = 5 (4 bytes)
        - message id = 4 (1 byte)
        - piece index = zero based index of the piece (4 bytes)"""
    def __init__(self, piece_index: int):
        super(Have, self).__init__(5, 4)
        self.piece_index = piece_index

    def to_bytes(self) -> bytes:
        return pack(">IBI",
                    self.length,
                    self.message_id,
                    self.piece_index)
    @classmethod
    def from_bytes(cls, buffer: bytes):
        length, message_id, piece_index = unpack(">IBI", buffer)
        if message_id == 4 and length == 5:
            return cls(piece_index)
        raise ValueError("Invalid binary format for Have message")


class BitField(Message):
    """BITFIELD = <length><message id><bitfield>
        - length = 1 + bitfield_size (5 bytes)
        - message id = 5 (1 byte)
        - bitfield = bitfield representing downloaded pieces (bitfield_size bytes)"""
    def __init__(self, bitfield: bytes, bitfield_size: int):
        super(BitField, self).__init__(1 + bitfield_size, 5)
        self.bitfield_size = bitfield_size
        self.bitfield = bitfield

    def to_bytes(self) -> bytes:
        return pack(">IB{}s".format(self.bitfield_size),
                    self.length,
                    self.message_id,
                    self.bitfield)

    @classmethod
    def from_bytes(cls, buffer: bytes):
        length, = unpack(">I", buffer[0:4])
        if length > 1:
            message_id, bitfield, = unpack(">B{}s".format(length-1), buffer[4:])
            if message_id == 5:
                return BitField(bitfield, length-1)
        raise ValueError("Invalid binary format for Bitfield message")


class Request(Message):
    """REQUEST = <length><message id><piece index><block offset><block length>
        - length = 13 (4 bytes)
        - message id = 6 (1 byte)
        - piece index = zero based piece index (4 bytes)
        - block offset = zero based of the requested block (4 bytes)
        - block length = length of the requested block (4 bytes)"""
    def __init__(self, piece_index: int, block_offset: int, block_length: int):
        super(Request, self).__init__(13, 6)
        self.piece_index = piece_index
        self.block_offset = block_offset
        self.block_length = block_length

    def to_bytes(self) -> bytes:
        return pack(">IBIII",
                    self.length,
                    self.message_id,
                    self.piece_index,
                    self.block_offset,
                    self.block_length)

    @classmethod
    def from_bytes(cls, buffer: bytes):
        length, message_id, piece_index, block_offset, block_length = unpack(">IBIII", buffer)
        if message_id == 6 and length == 13:
            return Request(piece_index, block_offset, block_length)
        raise ValueError("Invalid binary format for Request message")


class Piece(Message):
    """PIECE = <length><message id><piece index><block offset><block>
        - length = 9 + block length (4 bytes)
        - message id = 7 (1 byte)
        - piece index =  zero based piece index (4 bytes)
        - block offset = zero based of the requested block (4 bytes)
        - block = block as a bytestring or bytearray (block_length bytes)"""
    def __init__(self, block_length: int, piece_index: int, block_offset: int, block: bytes):
        super(Piece, self).__init__(9+block_length, 7)
        self.block_length = block_length
        self.piece_index = piece_index
        self.block_offset = block_offset
        self.block = block

    def to_bytes(self) -> bytes:
        return pack(">IBII{}s".format(self.block_length),
                    self.length,
                    self.message_id,
                    self.piece_index,
                    self.block_offset,
                    self.block)

    @classmethod
    def from_bytes(cls, buffer: bytes):
        length, = unpack(">I", buffer[0:4])
        if length > 9:
            block_length = length - 9
            message_id, piece_index, block_offset, block = unpack(">BII{}s".format(block_length),
                                                                  buffer[4:])
            if message_id == 7:
                return Piece(block_length, piece_index, block_offset, block)
        raise ValueError("Invalid binary format for Piece message")


class Cancel(Message):
    """CANCEL = <length><message id><piece index><block offset><block length>
        - length = 13 (4 bytes)
        - message id = 8 (1 byte)
        - piece index = zero based piece index (4 bytes)
        - block offset = zero based of the requested block (4 bytes)
        - block length = length of the requested block (4 bytes)"""
    def __init__(self, piece_index: int, block_offset: int, block_length: int):
        super(Cancel, self).__init__(13, 8)
        self.piece_index = piece_index
        self.block_offset = block_offset
        self.block_length = block_length

    def to_bytes(self) -> bytes:
        return pack(">IBIII",
                    self.length,
                    self.message_id,
                    self.piece_index,
                    self.block_offset,
                    self.block_length)

    @classmethod
    def from_bytes(cls, buffer: bytes):
        length, message_id, piece_index, block_offset, block_length = unpack(">IBIII", buffer)
        if message_id == 8 and length == 13:
            return Cancel(piece_index, block_offset, block_length)
        raise ValueError("Invalid binary format for Cancel message")


class Port(Message):
    """PORT = <length><message id><port number>
        - length = 5 (4 bytes)
        - message id = 9 (1 byte)
        - port number = listen_port (4 bytes)"""
    def __init__(self, listen_port: int):
        super(Port, self).__init__(5, 9)
        self.listen_port = listen_port

    def to_bytes(self) -> bytes:
        return pack(">IBI",
                    self.length,
                    self.message_id,
                    self.listen_port)

    @classmethod
    def from_bytes(cls, buffer: bytes):
        length, message_id, listen_port = unpack(">IBI", buffer)
        if message_id == 9 and length == 5:
            return Port(listen_port)
        raise ValueError("Invalid binary format for Port message")


if __name__ == "__main__":
    m = Cancel(1, 2, 3)
    n = Cancel(1, 2, 3)
    print(m.to_bytes())
    print(Message.from_bytes(m.to_bytes()) == m)
    print(m == n)