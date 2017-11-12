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

    def __init__(self, torrent, reader: asyncio.StreamReader,
                 writer: asyncio.StreamWriter):
        self.reader = reader
        self.writer = writer
        self.ip, self.port = self.writer.get_extra_info('peername')

        self.torrent = torrent
        self.is_choked = True
        self.chokes_me = True
        self.is_interested = False
        self.interests_me = False
        self.bitfield = bytearray(b"\x00"*torrent.bitfield_size)

    def __repr__(self):
        return "Peer({}:{}, is_choked={}, chokes_me={})".format(self.ip,
                                                                self.port,
                                                                self.is_choked,
                                                                self.chokes_me)

    @classmethod
    async def from_ip(cls, loop, torrent, ip: str, port: int):
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
        return cls(torrent, reader, writer)

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

    async def exchange(self, torrent):
        self.write(HandShake(torrent.info_hash))

        self.write(BitField(torrent.bitfield, torrent.bitfield_size))

        async for message in self.read():
            await self.torrent.handle_message(message, self)


if __name__ == '__main__':
    pass