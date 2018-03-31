"""
Download a single file from the internet
"""
import asyncio
import concurrent.futures
import logging
import os.path
import shutil
import sys

from tempfile import mkdtemp, gettempdir

EXAMPLES_DIR = os.path.dirname(os.path.abspath(__file__))
# Add the parent directory of the current file to sys.path so that we can
# import pyto even if it is not installed
sys.path.insert(0, os.path.join(EXAMPLES_DIR, os.path.pardir))
from pyto.torrent import Torrent


DATA_DIR = os.path.join(EXAMPLES_DIR, 'data')
arch_torrent = os.path.join(DATA_DIR, "archlinux-2018.03.01-x86_64.iso.torrent")


def main():
    logfile = os.path.join(gettempdir(), "PyTo.log")
    logging.basicConfig(
        level=logging.INFO,
        format="[%(asctime)s] %(levelname)s [%(name)s.%(funcName)s:%(lineno)d] "
               "%(message)s",
        datefmt="%H:%M:%S",
        filename=logfile,
        filemode='w')
    logging.getLogger().addHandler(logging.StreamHandler())
    logging.info("Logging to {}".format(logfile))

    loop = asyncio.get_event_loop()
    loop.set_debug(False)
    executor = concurrent.futures.ThreadPoolExecutor()
    loop.set_default_executor(executor)

    async def hypervisor():
        dir = mkdtemp()

        t = await Torrent.create(arch_torrent, dir)
        f = asyncio.ensure_future(t.download(6881))

        item = ""
        while item != "EVENT_DOWNLOAD_COMPLETE" and item != "EVENT_END":
            item = await t.queue.get()

        if item == "EVENT_END":
            raise ValueError

        await t.stop()
        await f

        shutil.rmtree(dir)

    loop.run_until_complete(hypervisor())

    loop.stop()
    loop.close()


if __name__ == '__main__':
    main()
