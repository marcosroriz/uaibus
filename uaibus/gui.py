#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
import threading
from datetime import datetime
from kivy.app import App
from kivy.uix.screenmanager import ScreenManager, Screen
from kivy.properties import BoundedNumericProperty, NumericProperty, StringProperty
from uaibus.cli import UaiController
from uaibus.scan import Scan
from uaibus.gps import GPS
from uaibus.csv_command import CSVCommand


# Make background color white
from kivy.core.window import Window
Window.clearcolor = (1, 1, 1, 1)

# Main Application Reference (created at __init__)
app = None

# Logger
logger = logging.getLogger("uaibus")


# Logging Info
def setuplog():
    log_msg_format = 'UAI-FI GUI :: %(asctime)s :: %(name)20s :: %(message)s'
    log_date_format = '%Y-%m-%d %H:%M:%S'
    logging.basicConfig(format=log_msg_format, datefmt=log_date_format)
    logger = logging.getLogger("uaibus")
    logger.setLevel(logging.INFO)
    logger.error("HIH")
    logger.info("Hdfadfsafsa")


# Get GUI params
def get_gui_params():
    moinface = str(app.root.get_screen("scaniface").moniface)
    gpsiface = str(app.root.get_screen("gpsiface").gpsiface)
    filename = "uai-fi.out." + \
               str(app.root.get_screen("filenumber").filenumber) + ".csv"

    datepickscreen = app.root.get_screen("datepicker")
    datehour = datepickscreen.hour
    datemin = datepickscreen.minutes
    datesec = datepickscreen.seconds

    date = datetime.now().replace(hour=datehour, minute=datemin, second=datesec)
    return (moinface, gpsiface, filename, date)


class Init(Screen):
    pass


class ScanIface(Screen):
    moniface = StringProperty("mon0")


class GPSIface(Screen):
    gpsiface = StringProperty("/dev/ttyUSB1")


class FileNumber(Screen):
    filenumber = BoundedNumericProperty(0, min=0, max=1000, errorvalue=0)


class DatePicker(Screen):
    hour = BoundedNumericProperty(0, min=0, max=24, errorvalue=0)
    minutes = BoundedNumericProperty(0, min=0, max=60, errorvalue=0)
    seconds = BoundedNumericProperty(0, min=0, max=60, errorvalue=0)


class Review(Screen):
    def on_enter(self):
        moniface, gpsiface, filename, date = get_gui_params()
        self.ids.reviewscaniface.text = moniface
        self.ids.reviewgpsiface.text = gpsiface
        self.ids.reviewfilename.text = filename
        self.ids.reviewdate.text = date.strftime("%H:%M:%S")


class Start(Screen):
    pkgcount = NumericProperty(0)

    def run(self):
        # Boot config
        self.controller.boot()

        # Enter main loop
        self.controller.loop(beaconcount=self.increment_pkg_count)

    def increment_pkg_count(self):
        self.pkgcount = self.pkgcount + 1

    def close(self):
        self.controller.close()
        app.root.current = "init"

    def on_enter(self):
        try:
            moniface, gpsiface, outfilename, date = get_gui_params()
            logger.info("Parameters")
            logger.info("Wi-Fi Interface: " + moniface)
            logger.info("GPS: " + gpsiface)
            logger.info("Output File: " + outfilename)

            # Create our scanner
            self.scan = Scan(moniface)

            # Create GPS module
            self.gps = GPS()

            # Create our controller
            self.controller = UaiController(self.scan, self.gps, outfilename)

            # CSV
            csvcommand = CSVCommand(outfilename)
            self.controller.addcommand(csvcommand)

            # Start processes
            self.t = threading.Thread(target=self.run)
            self.t.start()
        except Exception as ex:
            logger.error("Received an exception")
            logger.error(ex)


class UaiGUI(ScreenManager):
    pass


class GuiApp(App):
    pass


if __name__ == '__main__':
    # Setup Log
    setuplog()
    logger.info("OIv2")

    # Start the GUI App
    app = GuiApp()
    app.run()
