"""
Peer module

An instance of the Peer class represents a member of the network
"""
import asyncio
import logging

from pyto.messages import Message, KeepAlive, Choke, Unchoke, Interested, NotInterested, Have, \
                          BitField, Request, Piece, Cancel, Port, HandShake, decode_length, LENGTH_PREFIX

from typing import List, Union, AsyncIterable

PeerConnectErrors = (ConnectionRefusedError,
                     ConnectionAbortedError,
                     ConnectionError,
                     ConnectionResetError,
                     TimeoutError,
                     OSError,
                     asyncio.TimeoutError)

PeerWriteErrors = (ConnectionResetError,)


module_logger = logging.getLogger(__name__)

REQUEST_TIMEOUT = 10
KEEPALIVE_TIMEOUT = 120


class PeerAdapter(logging.LoggerAdapter):
    """Add the port and ip of the Peer to logger messages"""
    def process(self, msg, kwargs):
        header = '{:>20} {:>15}:{:<5} {}'.format(self.extra['name'],
                                                 self.extra['ip'],
                                                 self.extra['port'], msg)
        return header, kwargs


class Peer:
    peer_id = 0

    def __init__(self, ip: str, port: int, reader, writer, name=""):
        self.id = Peer.peer_id
        Peer.peer_id += 1

        # Networking
        self.reader: Union[asyncio.StreamReader, None] = reader
        self.writer: Union[asyncio.StreamWriter, None] = writer
        self.ip = ip
        self.port = port
        self.buffer = b""

        # Peer status
        # True if the peer initiated the connection
        self.initiated = True
        self.handshake_done = False
        self.is_choked = True
        self.chokes_me = True
        self.is_interested = False
        self.interests_me = False
        self.pieces = set()

        # Requests sent
        self.pending = set()
        self.pending_target = 30

        extra = {
            'name': name,
            'ip': self.ip,
            'port': self.port
        }
        self.logger = PeerAdapter(module_logger, extra)
        if not (reader is None and writer is None):
            self.logger.info("Peer already connected")

    def __repr__(self) -> str:
        return "Peer({}:{}, is_choked={}, chokes_me={})".format(self.ip,
                                                                self.port,
                                                                self.is_choked,
                                                                self.chokes_me)

    async def connect(self):
        if self.reader is None and self.writer is None:
            try:
                coro = asyncio.open_connection(self.ip, self.port)
                self.reader, self.writer = await asyncio.wait_for(coro, REQUEST_TIMEOUT)
            except PeerConnectErrors as e:
                self.logger.debug("Connection failed: {}".format(e))
                raise ConnectionError("Connection failed")
            self.logger.info("Established connection")
            self.initiated = False

    @classmethod
    async def from_ip(cls, ip: str, port: int, name=""):
        p = cls(ip, port, None, None, name)
        await p.connect()
        return p

    async def read_exactly(self, nbr_bytes: int) -> bytes:
        """Read nbr_bytes from the peer

        Raise EOFError in case of error or when the connection is closed"""
        try:
            # TODO: timeout
            coro = self.reader.readexactly(nbr_bytes)
            data = await asyncio.wait_for(coro, REQUEST_TIMEOUT)
        except PeerConnectErrors as e:
            self.logger.debug("readexactly() failed: {}".format(e))
            self.close()
            raise EOFError

        if self.reader.at_eof():
            raise EOFError

        return data

    async def read_messages(self) -> AsyncIterable:
        """"Return Messages received from the peer"""
        try:
            data = await self.read_exactly(HandShake.length_v1)
        except EOFError:
            return

        try:
            message = HandShake.from_bytes(data)
        except ValueError:
            self.logger.error("Received invalid message: {}".format(str(data)))
            return
        self.logger.debug("Message received: {}".format(str(message)))
        yield message

        while True:
            try:
                data = await self.read_exactly(LENGTH_PREFIX)
                message_length = decode_length(data)
                data = await self.read_exactly(message_length)
            except EOFError:
                break

            try:
                message = Message.from_bytes(data)
            except ValueError:
                self.logger.error("Received invalid message: {}".format(str(data)))
                break

            self.logger.debug("Message received: {}".format(str(message)))
            yield message

    async def messages(self) -> AsyncIterable:
        """Yield a message read on the network after updating the Peer instance"""
        async for message in self.read_messages():
            try:
                self.handle_message(message)
            except ValueError as e:
                self.logger.error("invalid message: {}".format(str(e)))
                break
            yield message

    async def write(self, messages: List[Message]):
        """Send all listed messages to the peer

        Might raise any exception in PeerWriteErrors"""
        for m in messages:
            self.logger.debug("write: {}".format(str(m)))

        bytes_messages = b"".join(map(lambda m: m.to_bytes(), messages))
        self.writer.write(bytes_messages)
        await self.writer.drain()

    async def send(self, messages: List[Message]):
        """Send messages on the network after updating the Peer instance"""
        for m in messages:
            if isinstance(m, Request):
                self.pending.add((m.piece_index, m.block_offset))

        try:
            await self.write(messages)
        except PeerWriteErrors as e:
            self.logger.debug("write() failed: {}".format(str(e)))
            raise

    def close(self):
        self.logger.debug("Connection closed")
        self.writer.close()

    def handle_message(self, message: Message):
        # TODO: Maybe move this check somewhere more appropriate
        if not self.handshake_done:
            if isinstance(message, HandShake):
                self.handshake_done = True
            else:
                raise ValueError("Invalid message")
        else:
            handler_name = '_handle_' + message.__class__.__name__
            try:
                handler = getattr(self, handler_name)
            except AttributeError:
                self.logger.error("No handler found for message: {}".format(message))
                raise NotImplemented("Missing handler for a Message subclass")
            handler(message)

    def _handle_Choke(self, _: Choke):
        self.chokes_me = True

    def _handle_Unchoke(self, _: Unchoke):
        self.chokes_me = False

    def _handle_Interested(self, _: Interested):
        self.is_interested = True

    def _handle_NotInterested(self, _: NotInterested):
        self.is_interested = False

    def _handle_Have(self, message: Have):
        self.pieces.add(message.piece_index)

    def _handle_BitField(self, message: BitField):
        self.pieces = message.pieces

    def _handle_Piece(self, message: Piece):
        try:
            self.pending.remove((message.piece_index, message.block_offset))
        except KeyError:
            raise ValueError("Received unrequested piece")

    def _handle_KeepAlive(self, _: KeepAlive):
        pass

    def _handle_Request(self, _: Request):
        pass

    def _handle_Cancel(self, _: Cancel):
        pass

    def _handle_Port(self, _: Port):
        pass

    def is_connected(self):
        return not (self.reader is None and self.writer is None)


if __name__ == '__main__':
    pass
