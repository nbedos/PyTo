"""
Main module for PyTo

Executing this module launches the download of the last Archlinux installation file and is a good
way to see PyTo working.
"""
import asyncio
import concurrent.futures
import logging

from shutil import rmtree
from tempfile import mkdtemp, gettempdir
from os.path import join

from Torrent import download, init

arch_torrent = "./data/torrent files/archlinux-2017.11.01-x86_64.iso.torrent"

if __name__ == '__main__':
    logfile = join(gettempdir(), "PyTo.log")
    logging.basicConfig(
        level=logging.DEBUG,
        format="[%(asctime)s] %(levelname)s [%(name)s.%(funcName)s:%(lineno)d] "
               "%(message)s",
        datefmt="%H:%M:%S",
        filename=logfile,
        filemode='w')
    logging.getLogger().addHandler(logging.StreamHandler())
    logging.info("Logging to {}".format(logfile))

    dir = mkdtemp()

    loop = asyncio.get_event_loop()
    executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
    loop.set_default_executor(executor)

    t = init(arch_torrent, dir)
    loop.run_until_complete(download(loop, t, 6881, end_when_complete=True))

    loop.close()
    rmtree(dir)
