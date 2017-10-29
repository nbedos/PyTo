from struct import pack, unpack


class Message:
    def __init__(self, length, message_id):
        if length >= 0:
            self.length = length
        else:
            raise ValueError("Message length must be >= 0")

        if (message_id is None) or isinstance(message_id, int):
            self.message_id = message_id
        else:
            raise TypeError("message_id must be an integer or None")

    #TODO: Check this - https://stackoverflow.com/questions/390250/elegant-ways-to-support-equivalence-equality-in-python-classes
    def __eq__(self, other):
        """Override the default Equals behavior"""
        if isinstance(other, self.__class__):
            return self.__dict__ == other.__dict__
        return NotImplemented

    def __ne__(self, other):
        """Define a non-equality test"""
        if isinstance(other, self.__class__):
            return not self.__eq__(other)
        return NotImplemented

    #def __hash__(self):
    #    """Override the default hash behavior (that returns the id or the object)"""
    #    return hash(tuple(sorted(self.__dict__.items())))

    def __repr__(self):
        return "{0}: {1}".format(self.__class__, sorted(self.__dict__.items()))

    def to_bytes(self):
        if self.message_id is None:
            return pack(">I", self.length)
        else:
            return pack(">IB", self.length, self.message_id)

    @classmethod
    def from_bytes(cls, buffer):
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

        # Second, check if we've got the full message in the buffer
        if buffer_length < LENGTH_SIZE + message_length:
            return None, buffer

        # At this point message_length is at least 1 so we can read the message_id from the buffer
        message_id, = unpack(">B", buffer[LENGTH_SIZE:LENGTH_SIZE+1])
        PAYLOAD_OFFSET = LENGTH_SIZE+1
        rest_offset = LENGTH_SIZE + message_length
        # CHOKE

        """from_bytes_funcs = {
            0: Choke.from_bytes,
            1: Unchoke.from_bytes,
            2: Interested.from_bytes,
            3: NotInterested.from_byte,
            4: Have.from_bytes,
            5: BitField.from_bytes,
            6: Request.from_bytes,
            7: Piece.from_bytes,
            8: Cancel.from_bytes,
            9: Port.from_bytes
        }
        
        try:
            return from_bytes_funcs[message_length]
        except KeyError:
            pass
        
        raise ValueError("Invalid message id")"""

        if message_id == 0 and message_length == 1:
            return Choke(), buffer[rest_offset:]
        # UNCHOKE
        elif message_id == 1 and message_length == 1:
            return Unchoke(), buffer[rest_offset:]
        # INTERESTED
        elif message_id == 2 and message_length == 1:
            return Interested(), buffer[rest_offset:]
        # NOT INTERESTED
        elif message_id == 3 and message_length == 1:
            return NotInterested(), buffer[rest_offset:]
        # HAVE
        elif message_id == 4 and message_length == 5:
            piece_index, = unpack(">I", buffer[PAYLOAD_OFFSET:PAYLOAD_OFFSET+4])
            return Have(piece_index), buffer[rest_offset:]
        # BITFIELD
        elif message_id == 5:
            bitfield_size = message_length-1
            bitfield = buffer[PAYLOAD_OFFSET:PAYLOAD_OFFSET+bitfield_size]
            return BitField(bitfield, bitfield_size), buffer[rest_offset:]
        # REQUEST
        elif message_id == 6 and message_length == 13:
            piece_index, block_offset, block_length = unpack(">III", buffer[PAYLOAD_OFFSET:PAYLOAD_OFFSET+message_length-1])
            return Request(piece_index, block_offset, block_length), buffer[rest_offset:]
        # PIECE
        elif message_id == 7 and message_length > 9:
            block_length = message_length - 9
            piece_index, block_offset, block = unpack(">II{}s".format(block_length), buffer)
            return Piece(block_length, piece_index, block_offset, block), buffer[rest_offset:]
        # CANCEL
        elif message_id == 8 and message_length == 13:
            piece_index, block_offset, block_length = unpack(">III", buffer[PAYLOAD_OFFSET:PAYLOAD_OFFSET+message_length-1])
            return Cancel(piece_index, block_offset, block_length), buffer[rest_offset:]
        # PORT
        elif message_id == 9 and message_length == 5:
            listen_port = unpack(">I", buffer[PAYLOAD_OFFSET:PAYLOAD_OFFSET+message_length-1])
            return Port(listen_port), buffer[rest_offset:]

        raise ValueError("Invalid message")


class KeepAlive(Message):
    """KEEP_ALIVE = <length>
        - length = 0 (4 bytes)"""
    def __init__(self):
        super(KeepAlive, self).__init__(0, None)


class Choke(Message):
    """CHOKE = <length><message id>
        - length = 1 (4 bytes)
        - message id = 0 (1 byte)"""
    def __init__(self):
        super(Choke, self).__init__(1, 0)


class Unchoke(Message):
    """UNCHOKE = <length><message id>
        - length = 1 (4 bytes)
        - message id = 1 (1 byte)"""
    def __init__(self):
        super(Unchoke, self).__init__(1, 1)


class Interested(Message):
    """INTERESTED = <length><message id>
        - length = 1 (4 bytes)
        - message id = 2 (1 byte)"""
    def __init__(self):
        super(Interested, self).__init__(1, 2)


class NotInterested(Message):
    """NOT INTERESTED = <length><message id>
        - length = 1 (4 bytes)
        - message id = 3 (1 byte)"""
    def __init__(self):
        super(NotInterested, self).__init__(1, 3)


class Have(Message):
    """ HAVE = <length><message id><piece index>
        - length = 5 (4 bytes)
        - message id = 4 (1 byte)
        - piece index = zero based index of the piece (4 bytes)"""
    def __init__(self, piece_index):
        super(Have, self).__init__(5, 4)
        self.piece_index = piece_index

    def to_bytes(self):
        return pack(">IBI",
                    self.length,
                    self.message_id,
                    self.piece_index)


class BitField(Message):
    """BITFIELD = <length><message id><bitfield>
        - length = 1 + bitfield_size (5 bytes)
        - message id = 5 (1 byte)
        - bitfield = bitfield representing downloaded pieces (bitfield_size bytes)"""
    def __init__(self, bitfield, bitfield_size):
        super(BitField, self).__init__(1 + bitfield_size, 5)
        self.bitfield_size = bitfield_size
        self.bitfield = bitfield

    def to_bytes(self):
        return pack(">IB{}s".format(self.bitfield_size),
                    self.length,
                    self.message_id,
                    self.bitfield)


class Request(Message):
    """REQUEST = <length><message id><piece index><block offset><block length>
        - length = 13 (4 bytes)
        - message id = 6 (1 byte)
        - piece index = zero based piece index (4 bytes)
        - block offset = zero based of the requested block (4 bytes)
        - block length = length of the requested block (4 bytes)"""
    def __init__(self, piece_index, block_offset, block_length):
        super(Request, self).__init__(13, 6)
        self.piece_index = piece_index
        self.block_offset = block_offset
        self.block_length = block_length

    def to_bytes(self):
        return pack(">IBIII",
                    self.length,
                    self.message_id,
                    self.piece_index,
                    self.block_offset,
                    self.block_length)


class Piece(Message):
    """PIECE = <length><message id><piece index><block offset><block>
        - length = 9 + block length (4 bytes)
        - message id = 7 (1 byte)
        - piece index =  zero based piece index (4 bytes)
        - block offset = zero based of the requested block (4 bytes)
        - block = block as a bytestring or bytearray (block_length bytes)"""
    def __init__(self, block_length, piece_index, block_offset, block):
        super(Piece, self).__init__(9+block_length, 7)
        self.block_length = block_length
        self.piece_index = piece_index
        self.block_offset = block_offset
        self.block = block

    def to_bytes(self):
        return pack(">IBII{}s".format(self.block_length),
                    self.length,
                    self.message_id,
                    self.piece_index,
                    self.block_offset,
                    self.block)


class Cancel(Message):
    """CANCEL = <length><message id><piece index><block offset><block length>
        - length = 13 (4 bytes)
        - message id = 8 (1 byte)
        - piece index = zero based piece index (4 bytes)
        - block offset = zero based of the requested block (4 bytes)
        - block length = length of the requested block (4 bytes)"""
    def __init__(self, piece_index, block_offset, block_length):
        super(Cancel, self).__init__(13, 8)
        self.piece_index = piece_index
        self.block_offset = block_offset
        self.block_length = block_length

    def to_bytes(self):
        return pack(">IBIII",
                    self.length,
                    self.message_id,
                    self.piece_index,
                    self.block_offset,
                    self.block_length)


class Port(Message):
    """PORT = <length><message id><port number>
        - length = 5 (4 bytes)
        - message id = 9 (1 byte)
        - port number = listen_port (4 bytes)"""
    def __init__(self, listen_port):
        super(Port, self).__init__(5, 9)
        self.listen_port = listen_port

    def to_bytes(self):
        return pack(">IBI",
                    self.length,
                    self.message_id,
                    self.listen_port)


if __name__ == "__main__":
    m = Cancel(1, 2, 3)
    n = Cancel(1, 2, 3)
    print(m.to_bytes())
    print(Message.from_bytes(m.to_bytes()) == m)
    print(m == n)