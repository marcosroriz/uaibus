#!/bin/bash

# Killing Network Processes
killall NetworkManager
killall wpa_supplicant
killall dhclient

# Start GPSD
/usr/sbin/gpsd /dev/ttyUSB0

# Start Monitor Mode
/usr/bin/mon0up

# Listen to Specific Channel
# iw phy phy0 interface add mon0 type monitor
# iw dev mon0 set channel 6

# Start Uai-Fi
env KIVY_BCM_DISPMANX_ID=4 python3 -m uaibus.gui
