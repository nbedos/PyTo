# PyTo, a Python BitTorrent client
### Project Goals
The main goal is to create a BitTorrent client software written in Python 3 using only the standard library, essentially for educational purposes.

BitTorrent is a protocol for peer to peer file sharing which makes this project quite interesting for several reasons :

 * **PyTo must act as a client and a server:** peer to peer file sharing means each peer in the network can download files and must share them
 * **Concurrency:** Sequentially downloading each piece of a file from a single peer is inefficient. BitTorrent clients download file pieces from tens of peers at a time. This means the software must implement concurrency.
 * **Decentralization:** The decentralized nature of the protocol encourages uses of rarely seen data structures such as the Distributed Hash Table (DHT).

### Personal Goals
My main goal is to learn more about Python 3, be it:
 * the language itself and the features that make it unique
 * the standard library
 * designing a software written in an object-oriented style
 * testing automation
 * good coding practices

### Progress

Functionalities:

 * **[implemented]** Parsing a Torrent file (single file mode)
 * **[implemented]** Querying the tracker to get a list of peers
 * **[implemented]** Connecting to peers and parsing their messages
 * **[in progress]** Checking on disk if the file has already been partially downloaded when creating a Torrent instance
 * **[to be done]** Handling spontaneous connections from peers
 * **[to be done]** Exchanging file pieces with peers
 * **[to be done]** Having the client download from other instances of itself for testing
 * **[to be done]** Download a whole file from the Internet
 * **[to be done]** Handling Torrent with multiple files
 * **[to be done]** Starting downloads from a magnet link
 * **[to be done]** ...


### BitTorrent resources

 * Specification on wiki.theory.org: https://wiki.theory.org/index.php/BitTorrentSpecification
 * Official specification: http://www.bittorrent.org/beps/bep_0003.html
 * Protocol extensions: http://www.bittorrent.org/beps/bep_0000.html

### Licence
PyTo is released under the BSD 3-clause licence.