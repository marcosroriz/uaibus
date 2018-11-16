#!/usr/bin/env python
# -*- coding: utf-8 -*-
from datetime import datetime
from kivy.app import App
from kivy.uix.screenmanager import ScreenManager, Screen
from kivy.properties import BoundedNumericProperty, \
                            StringProperty


# Make background color white
from kivy.core.window import Window
Window.clearcolor = (1, 1, 1, 1)

# Main Application Reference (created at __init__)
app = None


# Get GUI params
def get_gui_params():
    moinface = str(app.root.get_screen("scaniface").moniface)
    gpsiface = str(app.root.get_screen("gpsiface").gpsiface)
    filename = "uai-fi.out." + \
               str(app.root.get_screen("filenumber").filenumber) + ".csv"

    datepickscreen = app.root.get_screen("datepicker")
    datehour = datepickscreen.hour
    datemin  = datepickscreen.minutes
    datesec  = datepickscreen.seconds

    date = datetime.now().replace(hour=datehour,
                                  minute = datemin, second = datesec)
    return (moinface, gpsiface, filename, date)


class Init(Screen):
    pass


class ScanIface(Screen):
    moniface = StringProperty('mon0')


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
    pass


class UaiGUI(ScreenManager):
    pass


class GuiApp(App):
    pass


if __name__ == '__main__':
    app = GuiApp()
    app.run()
