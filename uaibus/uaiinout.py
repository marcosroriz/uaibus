#!/bin/env python
# import pudb
# pu.db

"""Plot script for uaibus log files."""
from math import atan2, radians, cos, sin, asin, sqrt
from sklearn.svm import SVC
from sklearn.externals import joblib
from sklearn.preprocessing import StandardScaler
import click
import csv
import random
import datetime
import folium
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
    stopid = None

    for id, stopdata in stops.items():
        stoplat = stopdata["lat"]
        stoplng = stopdata["lng"]

        stopdist = distance(lat, lng, stoplat, stoplng)

        if stopdist <= mindist:
            mindist = stopdist
            stopid = stopdata["pid"]

    return mindist, stopid


def getstops(stopsfile):
    stops = {}
    file = open(stopsfile, "r")
    freader = csv.DictReader(file)

    for line in freader:
        pid = int(line["pid"])
        id = str(line["id"])
        lat = float(line["latitude"])
        lng = float(line["longitude"])
        nome = str(line["nome"])

        stops[pid] = {"pid": pid, "id": id, "lat": lat,
                      "lng": lng, "nome": nome, "in": 0, "out": 0,
                      "inlist": [], "outlist": []}

    return stops


def parselog(logfile, stops, winsize, svm, scaler):
    tracker = {}
    file = open(logfile, "r")
    filereader = csv.DictReader(file)

    for line in filereader:
        if line["lat"] != "" and line["lng"] != "":
            # Raw data
            date = datetime.datetime.strptime(line["date"], '%Y-%m-%d %H:%M:%S')
            lat = float(line["lat"])
            lng = float(line["lng"])
            mac = str(line["mac"])
            rssi = int(line["rssi"])
            speed = float(line["speed"])

            # Derived data
            stopdist, stopid = closest(lat, lng, stops)
            wintravtime = 0     # Travelled time within beacons in time window
            wintravdist = 0     # Travelled distance within time window
            winfrequence = 1    # Number of beacons within time window
            totaltravtime = 0   # Total travelled time of this beacon
            totaltravdist = 0   # Total travelled distance of this beacon
            totalfrequence = 1  # Number of beacons sent by this user

            # Get the travelled dist in winsize (assume that trav = 0)
            oldestwinlat = lat
            oldestwinlng = lng
            oldestlat = lat
            oldestlng = lng

            # Check if we already see this mac
            if mac not in tracker:
                # New MAC address
                tracker[mac] = {}
                tracker[mac]["inside"] = False
                tracker[mac]["count"] = 0
                tracker[mac]["log"] = []
                tracker[mac]["points"] = []
                tracker[mac]["stops"] = []
            else:
                # Old MAC address
                # Get oldest position in wintime to compute trav dist and freq
                oldestlat = lat
                oldestlng = lng

                for prevdata in reversed(tracker[mac]["log"]):
                    prevdatadate = prevdata[0]
                    timediff = (date - prevdatadate).total_seconds()
                    if timediff <= winsize:
                        wintravtime = timediff
                        totaltravtime = timediff
                        winfrequence = winfrequence + 1
                        totalfrequence = totalfrequence + 1
                        oldestwinlat = prevdata[1]
                        oldestwinlng = prevdata[2]
                        oldestlat = prevdata[1]
                        oldestlng = prevdata[2]
                    else:
                        totaltravtime = timediff
                        totalfrequence = totalfrequence + 1
                        oldestlat = prevdata[1]
                        oldestlng = prevdata[2]

                # Travelled Distances
                wintravdist = distance(lat, lng, oldestwinlat, oldestwinlng)
                totaltravdist = distance(lat, lng, oldestlat, oldestlng)

            # Complete Beacon (Passenger Data)
            passengerdata = [date, lat, lng, mac, rssi, speed,
                             stopdist, wintravdist, wintravtime, winfrequence,
                             totaltravdist, totaltravtime, totalfrequence]

            # Check if beacon is inside or not
            scaldata = scaler.transform([[rssi, speed, wintravdist,
                                          wintravtime, winfrequence,
                                          totaltravdist, totaltravtime,
                                          totalfrequence]])
            outcome = svm.predict(scaldata)
            if outcome == [1]:
                if not tracker[mac]["inside"]:
                    tracker[mac]["inside"] = True
                    origstopid = stopid

                    if len(tracker[mac]["stops"]) > 0:
                        # origstopid = tracker[mac]["stops"][0] - 1
                        origstopid = tracker[mac]["stops"][0] - 1

                    stops[origstopid]["in"] = stops[origstopid]["in"] + 1
                    stops[origstopid]["inlist"] = stops[origstopid]["inlist"] + [mac]

                tracker[mac]["first"] = passengerdata
            else:
                # Check if it was previously inside
                if tracker[mac]["inside"]:
                    # Set out stop
                    stops[stopid]["out"] = stops[stopid]["out"] + 1
                    stops[stopid]["outlist"] = stops[stopid]["outlist"] + [mac]
                else:
                    pass

            tracker[mac]["stops"].append(stopid)
            tracker[mac]["count"] = tracker[mac]["count"] + 1
            tracker[mac]["log"].append(passengerdata)
            tracker[mac]["points"].append((lat, lng))
            tracker[mac]["last"] = passengerdata

    return stops


@click.command()
@click.option("--inlog",   default="uailog.csv", help="Input File")
@click.option("--instops", default="lane.csv", help="Bus stops stations file")
@click.option("--outlog",  default="map.html", help="Output File")
@click.option("--winsize", default=120,
              help="Maximum time (window size) in seconds between beacons ")
@click.option("--classifierfile", default="svmclassifier.pkl",
              help="Machine Learning Classifier")
@click.option("--scalerfile", default="scaler.pkl", help="Scaler file")
def main(inlog, instops, outlog, winsize, classifierfile, scalerfile):
    # Load classifier and scaler
    svm = joblib.load(classifierfile)
    scaler = joblib.load(scalerfile)

    # Read and parse stations
    stops = getstops(instops)

    # Read and parse log files in tracker
    stopcount = parselog(inlog, stops, winsize, svm, scaler)

    total = 0
    # Output
    for sid, stp in stopcount.items():
        print(sid, stp["in"])
        # print(sid, stp["out"])
        total = total + stp["in"]

    print("Total", total)


if __name__ == "__main__":
    main()
