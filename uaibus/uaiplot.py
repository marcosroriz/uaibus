#!/bin/env python

"""Plot script for uaibus log files."""
from math import atan2, radians, cos, sin, asin, sqrt
import click
import csv
import datetime
import folium
import folium.plugins
import logging
import numpy as np
import sys


def distance(lat1, lng1, lat2, lng2):
    R = 6371000  # raio da terra em metros
    rlat1 = radians(lat1)
    rlng1 = radians(lng1)
    rlat2 = radians(lat2)
    rlng2 = radians(lng2)

    dlat = rlat2 - rlat1
    dlng = rlng2 - rlng1

    a = sin(dlat / 2) ** 2 + cos(rlat1) * cos(rlat2) * sin(dlng / 2) ** 2
    c = 2 * atan2(sqrt(a), sqrt(1 - a))

    distance = R * c
    return distance


def closest(lat, lng, stops):
    mindist = sys.maxsize
    stopid  = None
    lineid  = None

    for id, stopdata in stops.items():
        stoplat = stopdata["lat"]
        stoplng = stopdata["lng"]

        stopdist = distance(lat, lng, stoplat, stoplng)

        if stopdist <= mindist:
            mindist = stopdist
            stopid  = stopdata["id"]
            lineid  = stopdata["pid"]

    return stopid, lineid


def getstops(stopsfile):
    stops   = {}
    file    = open(stopsfile, "r")
    freader = csv.DictReader(file)

    for line in freader:
        pid  = int(line["pid"])
        id   = str(line["id"])
        lat  = float(line["latitude"])
        lng  = float(line["longitude"])
        nome = str(line["nome"])

        stops[id] = {"pid": pid, "id": id, "lat": lat, "lng": lng, "nome": nome, "in": 0, "out": 0}

    return stops


def getlog(logfile, maxrssi):
    tracker = {}
    file = open(logfile, "r")
    filereader = csv.DictReader(file)

    for line in filereader:
        if line["lat"] != "" and line["lng"] != "":
            date  = datetime.datetime.strptime(line["date"], '%Y-%m-%d %H:%M:%S')
            lat   = float(line["lat"])
            lng   = float(line["lng"])
            mac   = str(line["mac"])
            rssi  = int(line["rssi"])
            speed = float(line["speed"])

            if mac not in tracker:
                if rssi >= maxrssi:
                    passengerdata = (date, lat, lng, mac, rssi, speed)
                    tracker[mac] = {}
                    tracker[mac]["log"]   = [passengerdata]
                    tracker[mac]["first"] = passengerdata
                    tracker[mac]["last"]  = passengerdata
            else:
                tracker[mac]["log"].append(passengerdata)
                tracker[mac]["last"] = passengerdata

    return tracker


@click.command()
@click.option("--inlog",   default="uailog.csv", help="Input File")
@click.option("--instops", default="lane.csv", help="Bus stops (stations) file")
@click.option("--outlog",  default="map.html", help="Output File")
@click.option("--maxrssi", default=-85, help="Maximum RSSI value that is considered valid for plotting packages")
def main(inlog, instops, outlog, maxrssi):
    # Config logging
    logging.basicConfig()
    logger = logging.getLogger("uaibus.uaiplot")
    logger.setLevel(logging.INFO)

    # Read and parse stations
    stops = getstops(instops)

    # Read and parse log files in tracker
    tracker = getlog(inlog, maxrssi)

    # Analyse the data
    # Plot the data
    map = folium.Map(location=[-16.68228, -49.2571096], zoom_start=12) # tiles='Stamen Terrain'
    mcluster = folium.plugins.MarkerCluster().add_to(map)

    odmatrix   = np.zeros((len(stops), len(stops)))
    termmatrix = np.zeros((len(stops), len(stops)))

    for mac, trackdata in tracker.items():
        firstdata = trackdata["first"]
        lastdata  = trackdata["last"]

        fdate, flat, flng, fmac, frssi, fspeed = firstdata
        ldate, llat, llng, lmac, lrssi, lspeed = lastdata

        if distance(flat, flng, llat, llng) >= 400:
            # Valid passenger
            # Let's compute the closest bus stop to its first and last signal
            enterstopid, enterlineid = closest(flat, flng, stops)
            exitstopid, exitlineid   = closest(llat, llng, stops)

            stops[enterstopid]["in"] = stops[enterstopid]["in"] + 1
            stops[exitstopid]["out"] = stops[exitstopid]["out"] + 1

            # Incrementing NP OD matrix
            odmatrix[enterlineid][exitlineid] = odmatrix[enterlineid][exitlineid] + 1
            if enterlineid <= 3:
                termmatrix[0][exitlineid] = termmatrix[0][exitlineid] + 1

            lpkt = folium.Marker([llat, llng], popup=str(lrssi) + "::" + lmac + "::" + str(ldate),
                                 icon=folium.Icon(color='red'))
            lpkt.add_to(mcluster)


    for id, stopdata in stops.items():
        stoplat   = stopdata["lat"]
        stoplng   = stopdata["lng"]
        stopname  = stopdata["nome"]
        stopenter = stopdata["in"]
        stopexit  = stopdata["out"]

        stopmsg = stopname + "<br />Entrou: " + str(stopenter) + "<br />Saiu: " + str(stopexit)
        lpkt = folium.Marker([stoplat, stoplng], popup=stopmsg)
        lpkt.add_to(map)

    np.savetxt("odmatrix.txt", odmatrix, fmt ='%.0f', delimiter=' ', newline='\n', header='', footer='')
    np.savetxt("termmatrix.txt", termmatrix, fmt ='%.0f', delimiter=' ', newline='\n', header='', footer='')

    map.save(outlog)


if __name__ == "__main__":
    main()
