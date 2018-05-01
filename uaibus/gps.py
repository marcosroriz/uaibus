# -*- coding: utf-8 -*-

"""GPS module."""
import datetime
import gpsd
import logging


class GPS:
    """GPS reading module.

    Attributes:
        gpsd            The gpsd daemon that is used to receive the GPS data
        lastposition    Last GPS position measured
        lasttimeupdate  Last time that the GPS has updated
    """

    def __init__(self):
        self.logger = logging.getLogger("uaibus.gps")

    def connect(self):
        try:
            gpsd.connect()
        except Exception:
            logging.error("Could not connect to gpsd daemon")

    def readposition(self):
        position = gpsd.get_current()
        self.lastposition = position
        self.lasttimeupdate = datetime.datetime.now()

        # [lat, lng, alt, speed, errorlat, errorlng, erroralt, errorspeed]
        posdata = [None] * 8
        try:
            if position.mode >= 2:
                # Location Measurements
                posdata[0] = position.lat
                posdata[1] = position.lon
                posdata[3] = position.hspeed

                # Error Measurements
                posdata[4] = position.error["y"]
                posdata[5] = position.error["x"]
                posdata[7] = position.error["s"]

            # Check if Altitude is present
            if position.mode >= 3:
                posdata[2] = position.alt
                posdata[6] = position.error['v']
        except Exception as ex:
            self.logger.error("Error when reading GPS data")
            self.logger.error(ex)

        return posdata
