# -*- coding: utf-8 -*-

"""Scan module."""
import logging
import queue
from concurrent.futures import ThreadPoolExecutor

from scapy.all import sniff
from scapy.layers.dot11 import Dot11


class Scan:
    """Scan a wireless interface for passenger' WiFi ProbeRequest data

    Attributes:
        wiface     The wireless interface that we are scanning
        scheduler  A thread pool to handles in parallel the pkt parsing
        pktqueue   A queue were the passenger's probe request pkts are stored
    """

    def __init__(self, wiface, poolsize=4):
        """Initializes a new Scanner instance.

        Args:
            wiface: The wireless interface to scan
            poolsize: the number of threads to use to handle each pool
            pktqueue: a queue to hold the pkts
        """
        self.wiface = wiface
        self.scheduler = ThreadPoolExecutor(max_workers=poolsize)
        self.pktqueue = queue.Queue()
        self.logger = logging.getLogger("uaibus.scan")

    def pkthandler(self, pkt):
        if pkt.haslayer(Dot11):
            if pkt.type == 0 and pkt.subtype == 4:
                if pkt.addr2 is not None:
                    try:
                        macaddr = pkt.addr2
                        rssistr = -(256 - ord(pkt.notdecoded[-4:-3]))
                        destaddr = pkt.info if pkt.info is not None else "undef"

                        pktdata = [macaddr, rssistr, destaddr]
                        self.pktqueue.put(pktdata)

                        pktstr = str(macaddr) + "," + str(rssistr) + "," + str(destaddr)
                        self.logger.info("Adding pkt data to queue: " + pktstr)
                    except IndexError:
                        # TODO: do this with logging
                        print("Index Error when parsing pkt")

    def readpacket(self):
        return self.pktqueue.get()

    def poolhandler(self, pkt):
        self.scheduler.submit(self.pkthandler, pkt)
        # self.pkthandler(pkt)

    def sniff(self):
        sniff(iface=self.wiface, prn=self.poolhandler)


if __name__ == '__main__':
    logger = logging.getLogger("uaibus.scan")
    logger.setLevel(logging.DEBUG)

    scan = Scan("wlp2s0mon")
    scan.sniff()
