"""
Main module for PyTo

Executing this module launches the download of the last Archlinux installation file and is a good
way to see PyTo working.
"""
import asyncio
import concurrent.futures
import logging

from shutil import rmtree
from tempfile import mkdtemp

from Torrent import download

arch_torrent = "./data/Torrent files/archlinux-2017.11.01-x86_64.iso.Torrent"

if __name__ == '__main__':
    logging.basicConfig(
        level=logging.DEBUG,
        format="[%(asctime)s] %(levelname)s [%(name)s.%(funcName)s:%(lineno)d] "
               "%(message)s",
        datefmt="%H:%M:%S",
        filename="PyTo.log",
        filemode='w')
    logging.getLogger().addHandler(logging.StreamHandler())

    dir = mkdtemp()

    loop = asyncio.get_event_loop()
    executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
    loop.set_default_executor(executor)

    loop.run_until_complete(download(loop, arch_torrent, 6881, dir, end_when_complete=True))

    loop.close()
    rmtree(dir)
