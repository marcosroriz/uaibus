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
        self.lastposition = None
        self.lasttimeupdate = datetime.datetime.now()
        self.logger = logging.getLogger("uaibus.gps")

    def connect(self):
        try:
            gpsd.connect()
        except Exception:
            logging.error("Could not connect to gpsd daemon")

    def readpacket(self):
        # [lat, lng, alt, speed, errorlat, errorlng, erroralt, errorspeed]
        pospkt = [None] * 8

        # Try to get position
        position = None
        try:
            position = gpsd.get_current()
            self.lastposition = position
            self.lasttimeupdate = datetime.datetime.now()
        except Exception:
            self.logger.error("Error getting position, using last position")
            position = self.lastposition

        # Parse position if not none
        try:
            if position is not None:
                # Grab latitude, longitude and speed data
                if position.mode >= 2:
                    # Location Measurements
                    pospkt[0] = position.lat
                    pospkt[1] = position.lon
                    pospkt[3] = position.hspeed

                    # Error Measurements
                    pospkt[4] = position.error["y"]
                    pospkt[5] = position.error["x"]
                    pospkt[7] = position.error["s"]

                # Check if Altitude is present
                if position.mode >= 3:
                    pospkt[2] = position.alt
                    pospkt[6] = position.error['v']
        except Exception as ex:
            self.logger.error("Error when reading GPS data")
            self.logger.error(ex)

        return pospkt
