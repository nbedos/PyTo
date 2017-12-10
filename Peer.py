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
        return '{:>15}:{:<5} {}'.format(self.extra['ip'], self.extra['port'], msg), kwargs


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

        self.logger = PeerAdapter(module_logger, {'ip': 'unknwon', 'port': 'unknown'})

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
            raise ValueError("Invalid arguments: Either (ip, port) or (reader, writer) must "
                             "be specified")
        self.ip, self.port = self.writer.get_extra_info('peername')
        self.logger = PeerAdapter(module_logger, {'ip': self.ip, 'port': self.port})
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
    except ConnectionError:
        logging.info("Connection failed for {}:{}".format(ip, port))
        return

    torrent.add_peer(p)
    torrent.logger.info("new peer added!")
    if initiated:
        await p.write([
            HandShake(torrent.info_hash),
            BitField(torrent.pieces, torrent.nbr_pieces)
        ])

    async for message in p.read():
        # Update the peer with information from the message
        try:
            p.handle_message(message)
        except ValueError as e:
            p.logger.error("invalid message: {}", str(e))
            break
        # Update the torrent with information from the message
        torrent.update_from_message(message)

        # Commit pieces to disk
        if torrent.pieces_to_write:
            await torrent.write_piece(loop)

        # Build a suitable answer
        messages = []
        for m in torrent.build_answer_to(message, initiated):
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
