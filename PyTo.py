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


if __name__ == '__main__':
    logging.basicConfig(
        level=logging.DEBUG,
        format="[%(asctime)s] %(levelname)s [%(name)s.%(funcName)s:%(lineno)d]@%(threadName)s "
               "%(message)s",
        datefmt="%H:%M:%S")

    dir = mkdtemp()

    loop = asyncio.get_event_loop()
    executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
    loop.set_default_executor(executor)

    c1 = download(loop, "./data/Torrent files/archlinux-2017.11.01-x86_64.iso.Torrent", 6881, dir)

    loop.run_until_complete(asyncio.gather(*c1))
    loop.close()
    rmtree(dir)