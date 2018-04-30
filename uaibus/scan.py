# -*- coding: utf-8 -*-

"""Scan module."""
from scapy.all import sniff
from scapy.layers.dot11 import Dot11
from concurrent.futures import ThreadPoolExecutor
import logging
import queue

class Scan:
    """Scan a wireless interface for passenger' WiFi ProbeRequest data

    Attributes:
        wiface      The wireless interface that we are scanning
        scheduler  A thread pool to handles in parallel the pkg parsing
        pkgqueue    A queue were the passenger's WiFi probe request pkgs are stored
    """

    def __init__(self, wiface, poolsize=4):
        """Initializes a new Scanner instance.

        Args:
            wiface: The wireless interface to scan
            poolsize: the number of threads to use to handle each pool
            pkgqueue: a queue to hold the pkgs
        """
        self.wiface     = wiface
        self.scheduler  = ThreadPoolExecutor(max_workers=poolsize, thread_name_prefix="ScanThread")
        self.pkgqueue   = queue.Queue()

    def pkghandler(self, pkt):
        if pkt.haslayer(Dot11):
            if pkt.type == 0 and pkt.subtype == 4:
                if pkt.addr2 is not None:
                    try:
                        macaddr  = pkt.addr2
                        rssistr  = -(256 - ord(pkt.notdecoded[-4:-3]))
                        destaddr = pkt.info if pkt.info is not None else "undef"

                        pkgtuple = (macaddr, rssistr, destaddr)
                        self.pkgqueue.put(pkgtuple)
                        logger.info("Adding pkg data to queue: " + pkgtuple)
                    except IndexError:
                        # TODO: do this with logging
                        print("Index Error when parsing PKG")

    def readpacket(self):
        return self.pkgqueue.get()

    def poolhandler(self, pkt):
        self.scheduler.submit(self.pkghandler, pkt)

    def sniff(self):
        sniff(iface=self.wiface, prn=self.poolhandler)

if __name__ == '__main__':
    logger = logging.getLogger("uaibus.scan")
    logger.setLevel(logging.DEBUG)

    scan = Scan("wlp2s0mon")
    scan.sniff()
