# -*- coding: utf-8 -*-

"""Console script for uaibus."""
import click
import logging
import threading
from uaibus.scan import Scan
from uaibus.gps import GPS
from uaibus.csv_command import CSVCommand
from concurrent.futures import ThreadPoolExecutor


class UaiController:
    def __init__(self, scan, gps, output):
        self.scan = scan
        self.gps = gps
        self.commands = []
        self.run = False
        self.scheduler = ThreadPoolExecutor(max_workers=4)
        self.logger = logging.getLogger("uaibus")

    def handlepkt(self, pkt):
        data = pkt
        for c in self.commands:
            c.execute(data)

    def addcommand(self, command):
        self.commands.append(command)

    def boot(self):
        # Start GPS
        self.gps.connect()

        # Start WiFi Scan
        self.t = threading.Thread(target=self.scan.sniff)
        self.t.start()

    def close(self):
        self.logger.info("Started Closing UAI-FI modules")

        self.run = False
        self.scan.close()
        self.t.join()
        # self.gps.close()
        for c in self.commands:
            c.close()

        self.logger.info("Finished Closing UAI-FI modules")

    def loop(self, run=True, beaconcount=None):
        self.run = run
        try:
            while run:
                # Read pkt data from scanner and gps
                wifipkt = self.scan.readpacket()
                gpspkt  = self.gps.readpacket()

                # Now, let's combine these data pkts
                pkt = wifipkt + gpspkt

                # Let's spawn a thread to handle output
                self.scheduler.submit(self.handlepkt, pkt)
                # self.handlepkt(pkt)

                # Update beacon count
                if beaconcount is not None:
                    beaconcount()

        except KeyboardInterrupt as kex:
            self.logger.error("Keyboard Interrupt")
            self.logger.error(kex)
        except Exception as ex:
            self.logger.error("Received an exception")
            self.logger.error(ex)


def setuplog():
    log_msg_format = '%(asctime)s :: %(name)20s :: %(message)s'
    log_date_format = '%Y-%m-%d %H:%M:%S'
    logging.basicConfig(format=log_msg_format, datefmt=log_date_format)
    logger = logging.getLogger("uaibus")
    logger.setLevel(logging.INFO)


@click.command()
@click.option("--wiface",  default="wlp2s0mon", help="Wireless interface to scan")
@click.option("--gpsfile", default="/dev/ttyUSB1", help="GPS device file")
@click.option("--usecli",  is_flag=True, help="Write log information to command line")
@click.option("--usecsv",  is_flag=True, help="Write log to CSV file")
@click.option("--output",  default="/root/uaibus/", type=click.Path(exists=True), help="Output directory for log files")
def main(wiface, gpsfile, usecli, usecsv, output):
    """Bootstrap script for configuring and running UaiBus."""

    # Create our scanner
    scan = Scan(wiface)

    # Create GPS module
    gps = GPS()

    # Create our controller
    controller = UaiController(scan, gps, output)

    # Using CLI output?
    if usecli:
        setuplog()

    # Using CSV output?
    if usecsv:
        csvcommand = CSVCommand(output)
        controller.addcommand(csvcommand)

    # Start processes
    controller.boot()

    # Enter main loop
    controller.loop()


if __name__ == "__main__":
    main()
