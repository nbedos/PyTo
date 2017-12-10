"""
Peer module

An instance of the Peer class represents a member of the network
"""
import asyncio
import datetime
import logging
import socket

from Messages import Message, KeepAlive, Choke, Unchoke, Interested, NotInterested, Have, \
                     BitField, Request, Piece, Cancel, Port, HandShake

from typing import List, Union, AsyncIterable
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
        # Networking
        self.socket = None
        self.ip = None
        self.port = None
        self.buffer = b""
        self.buffer_size = 4096

        # Peer status
        self.handshake_done = False
        self.is_choked = True
        self.chokes_me = True
        self.is_interested = False
        self.interests_me = False
        self.pieces = set([])

        # Requests sent
        self.pending = set()
        self.pending_target = 10

        self.logger = PeerAdapter(module_logger, {'ip': 'unknown', 'port': 'unknown'})

    def __repr__(self) -> str:
        return "Peer({}:{}, is_choked={}, chokes_me={})".format(self.ip,
                                                                self.port,
                                                                self.is_choked,
                                                                self.chokes_me)

    async def connect(self,
                      loop:   asyncio.AbstractEventLoop,
                      ip:     str,
                      port:   int,
                      peer_socket: Union[socket.socket, None]=None):
        if peer_socket is None:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setblocking(0)
            try:
                await loop.sock_connect(self.socket, (ip, port))
            except PeerConnectErrors as e:
                logging.debug("[{}:{}] Connection failed: {}".format(ip, port, e))
                raise ConnectionError("Connection failed")
        else:
            self.socket = peer_socket
            self.socket.setblocking(0)

        print("peer:", self.socket)
        self.ip = ip
        self.port = port
        self.logger = PeerAdapter(module_logger, {'ip': self.ip, 'port': self.port})
        self.logger.info("Established connection")

    async def read(self) -> bytes:
        """Read a chunk of data sent by the peer

        Raise EOFError in case of error or when the other end of the socket is closed"""
        loop = asyncio.get_event_loop()
        try:
            data = await loop.sock_recv(self.socket, self.buffer_size)
        except PeerConnectErrors as e:
            self.logger.debug("sock_recv() failed: {}".format(e))
            raise EOFError

        if not data:
            raise EOFError

        return data

    async def get_messages(self) -> AsyncIterable:
        """"Generator returning the Messages sent by the peer"""
        while self.socket:
            try:
                self.buffer += await self.read()
            except EOFError:
                self.logger.debug("Connection terminated unexpectedly")
                self.close()
                break

            while self.buffer:
                try:
                    message, self.buffer = Message.from_bytes(self.buffer)
                    if message is None:
                        break
                    else:
                        self.logger.debug("Message received: {}".format(str(message)))
                        yield message
                except ValueError:
                    self.logger.error("Received invalid message: {}".format(str(self.buffer)))
                    self.close()
                    break

    # Might raise any exception listed in PeerWriteErrors
    async def write(self, messages: List[Message]):
        for m in messages:
            self.logger.debug("write: {}".format(str(m)))

        bytes_messages = b"".join(map(lambda m: m.to_bytes(), messages))
        loop = asyncio.get_event_loop()
        await loop.sock_sendall(self.socket, bytes_messages)

    def close(self):
        self.logger.debug("Connection closed")
        if self.socket is not None:
            self.socket.close()
        self.socket = None

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
                   ip:        str,
                   port:      int,
                   socket:    Union[socket.socket, None]=None,
                   initiated: bool=False):
    p = Peer()
    loop = asyncio.get_event_loop()
    try:
        await p.connect(loop, ip=ip, port=port, peer_socket=socket)
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

    async for message in p.get_messages():
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
