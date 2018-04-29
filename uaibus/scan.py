# -*- coding: utf-8 -*-

"""Scan module."""
from scapy.all import sniff
from scapy.layers.dot11 import Dot11
from concurrent.futures import ThreadPoolExecutor
from threading import RLock


class Scan:
    """Scan a wireless interface for passenger data

    Attributes:
        wiface      The wireless interface that we are scanning
        pkgcount    The total number of probe requests packages that were scanned
        commands    A list of commands that will be executed when handling each new packet
        threadpool  A thread pool to spawn threads to handle each new packet
        lock        A reentering lock to control pkgcount accesses
    """

    def __init__(self, wiface="wlp2s0mon", poolsize=4):
        """Initializes a new Scanner instance.

        Args:
            wiface: The wireless interface to scan
            poolsize: the number of thread to use when handling packages
        """
        self.wiface = wiface
        self.pkgcount = 0
        self.commands = []
        self.threadpool = ThreadPoolExecutor(max_workers=poolsize)
        self.lock = RLock()

    def pkghandler(self, pkt):
        if pkt.haslayer(Dot11):
            if pkt.type == 0 and pkt.subtype == 4:
                if pkt.addr2 is not None:
                    self.lock.acquire()
                    print("Pacote ", self.pkgcount, "------------------------")
                    self.pkgcount = self.pkgcount + 1
                    self.lock.release()

                    sig_str = -(256 - ord(pkt.notdecoded[-2:-1]))
                    sig_str2 = -(256 - ord(pkt.notdecoded[-4:-3]))
                    print("addr2", pkt.addr2)
                    print("RSSI SHORT", sig_str)
                    print("RSSI SHORT", sig_str2)

    def poolhandler(self, pkt):
        self.threadpool.submit(self.pkghandler, pkt)

    def sniff(self):
        sniff(iface=self.wiface, prn=self.poolhandler)

if __name__ == '__main__':
    scan = Scan("wlp2s0mon", 4)
    scan.sniff()
