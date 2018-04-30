# -*- coding: utf-8 -*-

"""Console script for uaibus."""
import click
import logging
from uaibus.scan import Scan
from uaibus.csv_command import CSVCommand
from concurrent.futures import ThreadPoolExecutor

class UaiController:
    def __init__(self, scan, output, gps=None):
        self.scan = scan
        self.gps = gps
        self.commands = []
        self.scheduler = ThreadPoolExecutor(max_workers=4, thread_name_prefix="ControlThread")

    def handledata(self, pkt):
        data = pkt
        for c in self.commands:
            c.execute(data)

    def addcommand(self, command):
        self.commands.append(command)

    def boot(self):
        try:
            while True:
                # Read pkt data from scanner
                pkt = self.scan.readpacket()

                # Now, we need to combine this data with gps data
                # Let's spawn a thread to do this
                self.scheduler.submit(self.handledata, pkt)
        except KeyboardInterrupt:
            # TODO: Stop all commands, scanner and gps
            print('Interrupting!')



@click.command()
@click.option("--wiface",  default="wlp2s0mon", help="Wireless interface to scan")
@click.option("--gpsfile", default="/dev/ttyUSB1", help="GPS device file")
@click.option("--usecsv",  is_flag=True, help="Write log to CSV file")
@click.option("--output",  default="/root/uaibus/", type=click.Path(exists=True))
def main(wiface, gpsfile, usecsv, output):
    """Bootstrap script for configuring and running UaiBus."""

    # Create our scanner
    scan = Scan(wiface)

    # Create our controller
    controller = UaiController(scan, output)

    # Using CSV output?
    if usecsv:
        csvcommand = CSVCommand(output)
        controller.addcommand(csvcommand)

    # Enter main loop
    controller.boot()

if __name__ == "__main__":
    main()
