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

from Torrent import *

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

    loop = asyncio.get_event_loop()
    executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
    loop.set_default_executor(executor)

    async def hypervisor(loop):
        dir = mkdtemp()

        t = init(arch_torrent, dir)
        f = asyncio.ensure_future(download(loop, t, 6881))

        item = ""
        while item != "EVENT_DOWNLOAD_COMPLETE":
            item = await t.queue.get()

        stop(t, loop)
        await f

    loop.run_until_complete(hypervisor(loop))

    loop.stop()
    loop.close()
