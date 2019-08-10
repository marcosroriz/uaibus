# -*- coding: utf-8 -*-

"""CSV log module."""
import csv
import datetime
import logging
import os


class CSVCommand:
    """CSV command that writes the combined data of passenger's (WiFi ProbeRequest and GPS data)

    Attributes:
        csvfile     The CSV file
        csvwriter   A handler that can write to the csv file
        logcount    The total number of logging written so far
    """

    def __init__(self, output):
        self.initdate = datetime.datetime.now()
        log_date = self.initdate.strftime('%Y-%m-%d-%H-%M-%S')
        outname  = "uaibus.out." + log_date + ".csv"
        filename = os.path.join(".", output)

        self.csvfile   = open(filename, mode="a+")
        self.csvwriter = csv.writer(self.csvfile)
        self.logger    = logging.getLogger("uaibus.csv_command")

        # Write Header
        self.csvwriter.writerow(["date", "indate", "mac", "rssi", "dest",
                                 "lat", "lng", "alt", "speed", "errorlat",
                                 "errorlng", "erroralt", "errorspeed"])


    def execute(self, data):
        # Put in csv format
        current_date = datetime.datetime.now()
        current_date_formatted = current_date.strftime('%Y-%m-%d %H:%M:%S')

        # Delta
        delta = current_date - self.initdate
        totalSeconds = delta.seconds
        hours, remainder = divmod(totalSeconds, 3600)
        minutes, seconds = divmod(remainder, 60)
        delta_date_formatted = str(hours).rjust(2, '0') + ":" + str(minutes).rjust(2, '0') + ":" + str(seconds).rjust(2, '0')

        # Out
        csv_data = [delta_date_formatted] + [current_date_formatted] + data

        # Write to CSV
        self.csvwriter.writerow(csv_data)
        self.csvfile.flush()

        # Write to CLI
        self.logger.info(csv_data)


    def close(self):
        self.csvfile.flush()
        self.csvfile.close()
