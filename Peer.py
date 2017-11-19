"""
Peer module

An instance of the Peer class represents a member of the network
"""
import asyncio
import logging

from Messages import Message, KeepAlive, Choke, Unchoke, Interested, NotInterested, Have, \
                     BitField, Request, Piece, Cancel, Port, HandShake

connectionErrors = (ConnectionRefusedError,
                    ConnectionAbortedError,
                    ConnectionError,
                    ConnectionResetError,
                    TimeoutError,
                    OSError)

module_logger = logging.getLogger(__name__)


class PeerAdapter(logging.LoggerAdapter):
    """Add the port and ip of the Peer to logger messages"""
    def process(self, msg, kwargs):
        return '{:>15}:{:<5} {}'.format(self.extra['ip'], self.extra['port'], msg), kwargs


class Peer:
    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        self.reader = reader
        self.writer = writer
        self.ip, self.port = self.writer.get_extra_info('peername')

        self.is_choked = True
        self.chokes_me = True
        self.is_interested = False
        self.interests_me = False
        self.pieces = set([])
        self.handshake_done = False

        self.logger = PeerAdapter(module_logger, {'ip': self.ip, 'port': self.port})

    def __repr__(self) -> str:
        return "Peer({}:{}, is_choked={}, chokes_me={})".format(self.ip,
                                                                self.port,
                                                                self.is_choked,
                                                                self.chokes_me)

    @classmethod
    async def from_ip(cls, loop, ip: str, port: int):
        """Generate an instance of Peer from an ip address"""
        try:
            reader, writer = await asyncio.open_connection(ip, port, loop=loop)
        except connectionErrors as e:
            logging.debug("[{}:{}] Exception: {}".format(ip, port, e))
            return None
        return cls(reader, writer)

    async def read(self, buffer=b""):
        """"Generator returning the Messages received from the peer"""
        buffer_size = 4096

        while self.reader:
            try:
                buffer += await self.reader.read(buffer_size)
            except connectionErrors as e:
                self.logger.debug("Exception: {}".format(e))
                self.close()
                break

            while buffer:
                try:
                    message, buffer = Message.from_bytes(buffer)
                    if message is None:
                        break
                    else:
                        self.logger.debug("Message received: {}".format(str(message)))
                        yield message
                except ValueError:
                    self.logger.error("Received invalid message: {}".format(str(buffer)))
                    self.close()
                    break

            if self.reader is not None and self.reader.at_eof():
                self.close()
                break

    def write(self, message):
        self.logger.debug("write: {}".format(str(message)))
        # TODO: Check exceptions
        self.writer.write(message.to_bytes())

    def close(self):
        self.logger.debug("Connection closed")
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
            self.pieces.add(message.piece_index)
        elif isinstance(message, BitField):
            self.pieces = message.pieces

    async def exchange(self, torrent, initiated=False):
        if initiated:
            self.write(HandShake(torrent.info_hash))
            self.write(BitField(torrent.pieces, torrent.nbr_pieces))

        async for message in self.read():
            self.handle_message(message)
            messages = await torrent.handle_message(message, self.pieces, self.chokes_me, initiated)
            for m in messages:
                self.write(m)


if __name__ == '__main__':
    pass
