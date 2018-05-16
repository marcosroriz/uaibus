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

        # Try to get position from gpsd
        position = None
        try:
            position = gpsd.get_current()
        except Exception:
            self.logger.error("Error when polling position from gpsd")

        # Log position
        self.logger.info(position)
 
        # Check if GPS position is valid
        valid = False
        if position is None:
            self.logger.warning("Error when polling position")
        elif position.mode < 2:
            self.logger.warning("Received position, but without precision.")
        elif position.mode >= 2:
            valid = True
            self.lastposition = position
            self.lasttimeupdate = datetime.datetime.now()

        # If position is not valid, try to use the last valid one
        if not valid:
            self.logger.info("Trying to use last position")
            currentdate = datetime.datetime.now()
            diffdate = (currentdate - self.lasttimeupdate).total_seconds()
            self.logger.info("Last position was on: " + str(diffdate))

            # Use last one if diff <= 120 seconds
            if diffdate <= 120:
                position = self.lastposition

        # Parse position if it is not None
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
            else:
                # Position is None
                self.logger.error("Read position, but it is equal to None")
        except Exception as ex:
            self.logger.error("Error when reading GPS data")
            self.logger.error(ex)

        return pospkt

