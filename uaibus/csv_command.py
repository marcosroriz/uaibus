# -*- coding: utf-8 -*-

"""CSV log module."""
import csv
import datetime
import logging
import os
from threading import RLock


class CSVCommand:
    """CSV command that writes the combined data of passenger's (WiFi ProbeRequest and GPS data)

    Attributes:
        csvfile     The CSV file
        csvwriter   A handler that can write to the csv file
        logcount    The total number of logging written so far
    """

    def __init__(self, output):
        log_date = datetime.datetime.now().strftime('%Y-%m-%d-%H-%M-%S')
        outname  = "uaibus.out." + log_date + ".csv"
        filename = os.path.join(output, outname)

        self.csvfile   = open(filename, mode="xt")
        self.csvwriter = csv.writer(self.csvfile)
        self.pktcount  = 0
        self.pktlock   = RLock()
        self.logger    = logging.getLogger("uaibus.csv_command")

        # Write Header
        self.csvwriter.writerow(["pkgnumber", "date", "mac", "rssi", "dest", "lat", "lng"])


    def execute(self, data):
        # Increment the pkt count
        self.pktlock.acquire()
        current_pkt_count = self.pktcount
        self.pktcount = self.pktcount + 1
        self.pktlock.release()

        # Put in csv format
        current_date = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        csv_data = [current_pkt_count] + [current_date] + [x for x in data]

        # Write to CSV
        self.csvwriter.writerow(csv_data)
        self.csvfile.flush()

        # Write to CLI
        self.logger.info(csv_data)

    def close(self):
        self.csvfile.flush()
        self.csvfile.close()
        self.csvwriter.close()
