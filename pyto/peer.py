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
        return '{:>15}:{:<5} {}'.format(self.extra['ip'], self.extra['port'], msg), kwargs


class Peer:
    peer_id = 0

    def __init__(self, ip: str, port: int, reader, writer):
        self.id = Peer.peer_id
        Peer.peer_id += 1

        # Networking
        self.reader: Union[asyncio.StreamReader, None] = reader
        self.writer: Union[asyncio.StreamWriter, None] = writer
        self.ip = ip
        self.port = port
        self.buffer = b""

        # Peer status
        self.handshake_done = False
        self.is_choked = True
        self.chokes_me = True
        self.is_interested = False
        self.interests_me = False
        self.pieces = set()

        # Requests sent
        self.pending = set()
        self.pending_target = 30

        self.logger = PeerAdapter(module_logger, {'ip': self.ip, 'port': self.port})
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
                self.reader, self.writer = await asyncio.open_connection(self.ip, self.port)
            except PeerConnectErrors as e:
                self.logger.debug("Connection failed: {}".format(e))
                raise ConnectionError("Connection failed")
            self.logger.info("Established connection")

    @classmethod
    async def from_ip(cls, ip: str, port: int):
        p = cls(ip, port, None, None)
        await p.connect()
        return p

    async def read_exactly(self, nbr_bytes: int) -> bytes:
        """Read nbr_bytes from the peer

        Raise EOFError in case of error or when the connection is closed"""
        try:
            # TODO: timeout
            data = await self.reader.readexactly(nbr_bytes)
        except PeerConnectErrors as e:
            self.logger.debug("readexactly() failed: {}".format(e))
            self.close()
            raise EOFError

        if self.reader.at_eof():
            raise EOFError

        return data

    async def get_messages(self) -> AsyncIterable:
        """"Generator returning the Messages sent by the peer"""
        try:
            data = await self.read_exactly(HandShake.length_v1)
        except EOFError:
            return

        try:
            message = HandShake.from_bytes(data)
        except ValueError:
            self.logger.error("Received invalid message: {}".format(str(data)))
            return

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

    async def write(self, messages: List[Message]):
        """Send all listed messages to the peer

        Might raise any exception in PeerWriteErrors"""
        for m in messages:
            self.logger.debug("write: {}".format(str(m)))

        bytes_messages = b"".join(map(lambda m: m.to_bytes(), messages))
        self.writer.write(bytes_messages)
        await self.writer.drain()

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


# TODO: Cleanly end connection when the task is cancelled
async def exchange(torrent, p: Peer, initiated: bool=False):
    loop = asyncio.get_event_loop()

    torrent.add_peer(p)
    torrent.logger.info("new peer added!")
    if initiated:
        await p.write([
            HandShake(torrent.info_hash),
            BitField(torrent.piece_manager.pieces, torrent.piece_manager.nbr_pieces)
        ])

    async for message in p.get_messages():
        # Update the peer with information from the message
        try:
            p.handle_message(message)
        except ValueError as e:
            p.logger.error("invalid message: {}".format(str(e)))
            break

        # Update the torrent with information from the message
        torrent.update_from_message(message, p.id)

        # Commit pieces to disk
        if torrent.piece_manager.pieces_to_write:
            await torrent.write_piece(loop)
            await torrent.is_complete()

        # Build a suitable answer
        messages = []
        for m in torrent.build_answer_to(message, initiated, p.id):
            if isinstance(m, Piece):
                # Read disk to add missing info
                messages.append(await torrent.complement(m))
            else:
                messages.append(m)

        # Add requests
        messages += torrent.build_requests(p)

        # Update peer with messages to be sent
        for m in messages:
            if isinstance(m, Request):
                p.pending.add((m.piece_index, m.block_offset))

        # Send messages
        try:
            await p.write(messages)
        except PeerWriteErrors as e:
            p.logger.debug("write() failed: {}".format(str(e)))
            break

    torrent.remove_peer(p)
    p.close()


if __name__ == '__main__':
    pass
