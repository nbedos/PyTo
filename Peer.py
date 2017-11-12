"""
Peer module

An instance of the Peer class represents a member of the network
"""
import asyncio
import logging

from Messages import Message, KeepAlive, Choke, Unchoke, Interested, NotInterested, Have, \
                     BitField, Request, Piece, Cancel, Port, HandShake


class Peer:
    buffer_size = 4096

    def __init__(self, bitfield_size: int, reader: asyncio.StreamReader,
                 writer: asyncio.StreamWriter):
        self.reader = reader
        self.writer = writer
        self.ip, self.port = self.writer.get_extra_info('peername')

        self.is_choked = True
        self.chokes_me = True
        self.is_interested = False
        self.interests_me = False
        self.bitfield_size = bitfield_size
        self.bitfield = bytearray(b"\x00"*self.bitfield_size)
        self.handshake_done = False

    def __repr__(self) -> str:
        return "Peer({}:{}, is_choked={}, chokes_me={})".format(self.ip,
                                                                self.port,
                                                                self.is_choked,
                                                                self.chokes_me)

    @classmethod
    async def from_ip(cls, loop, bitfield_size: int, ip: str, port: int):
        """Generate an instance of Peer from an ip address"""
        try:
            reader, writer = await asyncio.open_connection(ip, port, loop=loop)
        except (ConnectionRefusedError,
                ConnectionAbortedError,
                ConnectionError,
                ConnectionResetError,
                TimeoutError,
                OSError) as e:
            logging.debug("[{}:{}] Exception: {}".format(ip, port, e))
            return None
        return cls(bitfield_size, reader, writer)

    async def read(self, buffer=b""):
        """"Generator returning the Messages received from the peer"""
        #logging.debug("[{}:{}] Buffer before: {}".format(self.ip, self.port, str(buffer)))
        while self.reader:
            try:
                buffer += await self.reader.read(Peer.buffer_size)
            except (ConnectionRefusedError,
                    ConnectionAbortedError,
                    ConnectionError,
                    ConnectionResetError,
                    TimeoutError,
                    OSError) as e:
                #logging.debug("[{}:{}] Exception: {}".format(self.ip, self.port, e))
                self.close()
                break

            if self.reader.at_eof():
                self.close()
                break

            #logging.debug("[{}:{}] Buffer during: {}".format(self.ip, self.port, str(buffer)))
            while buffer:
                try:
                    message, buffer = Message.from_bytes(buffer)
                    if message is None:
                        break
                    else:
                        logging.debug("[{}:{}] Message received: {}".format(self.ip,
                                                                            self.port,
                                                                            str(message)))
                        #logging.debug(
                        #    "[{}:{}] Buffer after: {}".format(self.ip, self.port, str(buffer)))
                        yield message
                except ValueError:
                    logging.error("[{}:{}] Received invalid message: {}".format(self.ip,
                                                                                self.port,
                                                                                str(buffer)))
                    self.close()
                    break

    def write(self, message):
        logging.debug("[{}:{}] write: {}".format(self.ip, self.port, str(message)))
        # TODO: Check exceptions
        self.writer.write(message.to_bytes())

    def close(self):
        logging.debug("[{}:{}] Connection closed".format(self.ip, self.port))
        if self.writer:
            self.writer.close()
        self.writer = None
        self.reader = None

    def handle_message(self, message: Message):
        if not self.handshake_done:
            if isinstance(message, HandShake):
                self.handshake_done = True
            else:
                raise ValueError("Invalid message")
        elif isinstance(message, KeepAlive):
            pass
        elif isinstance(message, Choke):
            self.chokes_me = True
        elif isinstance(message, Unchoke):
            self.chokes_me = False
        elif isinstance(message, Interested):
            self.is_interested = True
        elif isinstance(message, NotInterested):
            self.is_interested = False
        elif isinstance(message, Have):
            try:
                q, r = divmod(message.piece_index, 8)
                self.bitfield[q] += (128 >> r)
            except IndexError:
                raise ValueError("Invalid Have message")
        elif isinstance(message, BitField):
            if message.bitfield_size == self.bitfield_size:
                self.bitfield = bytearray(message.bitfield)
            else:
                raise ValueError("Invalid BitField message")

    async def exchange(self, torrent, initiated=False):
        if initiated:
            self.write(HandShake(torrent.info_hash))
            self.write(BitField(torrent.bitfield, torrent.bitfield_size))

        async for message in self.read():
            self.handle_message(message)
            messages = await torrent.handle_message(message, self.bitfield, initiated)
            for m in messages:
                self.write(m)


if __name__ == '__main__':
    pass