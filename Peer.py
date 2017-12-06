"""
Peer module

An instance of the Peer class represents a member of the network
"""
import asyncio
import datetime
import logging

from Messages import Message, KeepAlive, Choke, Unchoke, Interested, NotInterested, Have, \
                     BitField, Request, Piece, Cancel, Port, HandShake

from typing import List, Union
PeerConnectErrors = (ConnectionRefusedError,
                     ConnectionAbortedError,
                     ConnectionError,
                     ConnectionResetError,
                     TimeoutError,
                     OSError)

PeerWriteErrors = (ConnectionResetError,)


module_logger = logging.getLogger(__name__)


class PeerAdapter(logging.LoggerAdapter):
    """Add the port and ip of the Peer to logger messages"""
    def process(self, msg, kwargs):
        return msg, kwargs
        #return '{:>15}:{:<5} {}'.format(self.extra['ip'], self.extra['port'], msg), kwargs


class Peer:
    def __init__(self):
        self.reader = None
        self.writer = None
        self.ip = None
        self.port = None

        self.is_choked = True
        self.chokes_me = True
        self.is_interested = False
        self.interests_me = False
        self.pieces = set([])
        self.handshake_done = False

        self.pending_target = 10
        self.pending = set()

        self.logger = PeerAdapter(module_logger, {'ip': self.ip, 'port': self.port})

    def __repr__(self) -> str:
        return "Peer({}:{}, is_choked={}, chokes_me={})".format(self.ip,
                                                                self.port,
                                                                self.is_choked,
                                                                self.chokes_me)

    async def connect(self,
                      loop:   asyncio.AbstractEventLoop,
                      ip:     Union[str, None]=None,
                      port:   Union[int, None]=None,
                      reader: Union[asyncio.StreamReader, None]=None,
                      writer: Union[asyncio.StreamWriter, None]=None):
        if ip is not None and port is not None and (reader, writer) == (None, None):
            try:
                self.reader, self.writer = await asyncio.open_connection(ip, port, loop=loop)
            except PeerConnectErrors as e:
                logging.debug("[{}:{}] Connection failed: {}".format(ip, port, e))
                raise ConnectionError("Connection failed")

        elif reader is not None and writer is not None and (ip, port) == (None, None):
            self.reader = reader
            self.writer = writer
        else:
            print("connection failed")
            raise ValueError("Invalid arguments: Either (ip, port) or (reader, writer) must "
                             "be specified")
        self.ip, self.port = self.writer.get_extra_info('peername')
        self.logger.info("Established connection")

    async def read(self, buffer=b""):
        """"Generator returning the Messages received from the peer"""
        buffer_size = 4096

        while self.reader:
            try:
                buffer += await self.reader.read(buffer_size)
            except PeerConnectErrors as e:
                self.logger.debug("read() failed: {}".format(e))
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

    # Might raise any exception listed in PeerWriteErrors
    async def write(self, messages: List[Message]):
        for m in messages:
            self.logger.debug("write: {}".format(str(m)))

        bytes_messages = b"".join(map(lambda m: m.to_bytes(), messages))
        self.writer.write(bytes_messages)
        # Await drain() so that an exception is raised if something goes wrong
        await self.writer.drain()

    def close(self):
        self.logger.debug("Connection closed")
        if self.writer is not None:
            self.writer.close()
        self.writer = None
        self.reader = None

    # TODO: try functools.singledispatch implementation?
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
        elif isinstance(message, Piece):
            try:
                self.pending.remove((message.piece_index, message.block_offset))
            except KeyError:
                raise ValueError("Received unrequested piece")


# TODO: Cleanly end connection when the task is cancelled
async def exchange(torrent,
                   ip:        Union[str, None]=None,
                   port:      Union[int, None]=None,
                   reader:    Union[asyncio.StreamReader, None]=None,
                   writer:    Union[asyncio.StreamWriter, None]=None,
                   initiated: bool=False):
    p = Peer()
    loop = asyncio.get_event_loop()
    try:
        await p.connect(loop, ip=ip, port=port, reader=reader, writer=writer)
    except (ConnectionError, ValueError) as e:
        print(e)
        return

    torrent.add_peer(p)
    p.logger.info("new peer added!")
    if initiated:
        await p.write([
            HandShake(torrent.info_hash),
            BitField(torrent.pieces, torrent.nbr_pieces)
        ])

    async for message in p.read():
        try:
            p.handle_message(message)
        except ValueError as e:
            p.logger.error("invalid message: {}", str(e))
            break
        messages = await torrent.handle_message(message, initiated)
        messages += torrent.build_requests(p)
        for m in messages:
            if isinstance(m, Request):
                p.pending.add((m.piece_index, m.block_offset))
        try:
            await p.write(messages)
        except PeerWriteErrors as e:
            p.logger.debug("write() failed: {}".format(str(e)))
            break


if __name__ == '__main__':
    pass
