# -*- coding: utf-8 -*-

"""Scan module."""
import logging
import queue
import time
import threading
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
        self.stopevent = threading.Event()

    def pkthandler(self, pkt):
        if pkt.haslayer(Dot11):
            if pkt.type == 0 and pkt.subtype == 4:
                if pkt.addr2 is not None:
                    try:
                        macaddr = pkt.addr2
                        rssistr = -(256 - ord(pkt.notdecoded[-2:-1]))
                        destaddr = pkt.info if pkt.info is not None else "undef"

                        pktdata = [macaddr, rssistr, destaddr]
                        self.pktqueue.put(pktdata)

                        pktstr = str(macaddr) + "," + str(rssistr) + "," + str(destaddr)
                        self.logger.info("Adding pkt data to queue: " + pktstr)
                    except IndexError as iex:
                        self.logger.error("Index Error when parsing pkt")
                        self.logger.error(str(iex))
                    except Exception as ex:
                        self.logger.error("Received an error when handling pkg")
                        self.logger.error(str(ex))

    def readpacket(self):
        return self.pktqueue.get()

    def poolhandler(self, pkt):
        self.scheduler.submit(self.pkthandler, pkt)
        # self.pkthandler(pkt)

    def close(self):
        self.stopevent.set()

    def sniff(self):
        sniff(iface=self.wiface, prn=self.poolhandler, store=0,
              stop_filter=lambda x: self.stopevent.is_set())


if __name__ == '__main__':
    logging.basicConfig()
    logger = logging.getLogger("uaibus.scan")
    logger.setLevel(logging.DEBUG)

    scan = Scan("mon0")
    t = threading.Thread(target=scan.sniff)
    t.start()

    logger.info("Sleeping 10 seconds")
    time.sleep(10)

    logger.info("Closing Sniffer")
    scan.close()
    time.sleep(2)

    logger.info("Ensure that queue has same size in next 10 seconds")
    lengthBefore = scan.pktqueue.qsize()
    time.sleep(10)

    lengthAfter = scan.pktqueue.qsize()
    if lengthBefore == lengthAfter:
        logger.info("Queues have same size. Closed correctly")
    else:
        logger.error("Queues DOES NOT have same size. Closed INCORRECTLY")
