[![Build Status](https://travis-ci.org/nbedos/PyTo.svg?branch=master)](https://travis-ci.org/nbedos/PyTo)
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

Milestones:

 * **[Done]** Parse a Torrent file (single file mode)
 * **[Done]** Query the tracker to get a list of peers
 * **[Done]** Connect to peers and parse their messages
 * **[Done]** Check on disk if the file has already been partially downloaded when creating a Torrent instance
 * **[Done]** Accept spontaneous connections from peers
 * **[Done]** Have the client download from other instances of itself for testing
 * **[Done]** Download a whole file from the Internet (500 MB ISO downloaded at 30 MB/s)
 * **[Done]** Handle Torrents with multiple files
 * **[in progress]** Improve tracker requests:
    * ~~Use aiohttp instead of urllib for tracker requests (HTTP protocol)~~
    * Query trackers continuously instead of just once after creation of the Torrent instance
    * Add support for 'announce-list' key in metainfo files
    * Add a common interface for both HTTP and UDP trackers
    * Add support for UDP trackers (BEP 15)
 * **[to be done]** Implement a choking algorithm
 * **[to be done]** Implement DHT and add support for magnet links
 * **[to be done]** Setup an API to control the exchange of data (pause, restart, throttle...)
 * **[to be done]** Allow users to easily manage multiple simultaneous downloads
 * **[to be done]** ...
 

### BitTorrent resources

 * Specification on wiki.theory.org: https://wiki.theory.org/index.php/BitTorrentSpecification
 * Official specification: http://www.bittorrent.org/beps/bep_0003.html
 * Protocol extensions: http://www.bittorrent.org/beps/bep_0000.html

### Licence
PyTo is released under the BSD 3-clause licence.
