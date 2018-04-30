# -*- coding: utf-8 -*-

"""CSV log module."""
import csv
import datetime
import os

class CSVCommand:
    """CSV command that writes the combined data of passenger's (WiFi ProbeRequest and GPS data)

    Attributes:
        csvfile     The CSV file
        csvwriter   A handler that can write to the csv file
        logcount    The total number of logging written so far
    """

    def __init__(self, output):
        current_date = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        outname  = "out" + current_date + ".csv"
        filename = os.path.join(output, outname)

        self.csvfile   = open(filename)
        self.csvwriter = csv.writer(self.csvfile)
        self.logcount  = 0

        # Write Header
        self.csvwriter.writerow(["date,mac,rssi,dest,lat,lng"])


    def execute(self, data):
        # Write
        self.csvwriter.writerow([data])
        self.csvwriter.flush()

    def close(self):
        self.csvfile.close()
        self.csvwriter.close()
