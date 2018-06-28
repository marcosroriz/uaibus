#!/bin/env python
# import pudb
# pu.db

import csv
import datetime
import logging
import click
import sys
import numpy as np
from math import asin, atan2, cos, radians, sin, sqrt
import matplotlib.pyplot as plt
from mpl_toolkits.mplot3d import Axes3D


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

    for id, stopdata in stops.items():
        stoplat = stopdata["lat"]
        stoplng = stopdata["lng"]

        stopdist = distance(lat, lng, stoplat, stoplng)

        if stopdist <= mindist:
            mindist = stopdist

    return mindist


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

        stops[id] = {"pid": pid, "id": id, "lat": lat, "lng": lng,
                     "nome": nome, "in": 0, "out": 0}

    return stops


def getlog(logfile, stops, winsize):
    tracker = {}
    file = open(logfile, "r")
    filereader = csv.DictReader(file)

    for line in filereader:
        if line["lat"] != "" and line["lng"] != "":
            date = datetime.datetime.strptime(line["date"], '%Y-%m-%d %H:%M:%S')
            lat = float(line["lat"])
            lng = float(line["lng"])
            mac = str(line["mac"])
            rssi = int(line["rssi"])
            speed = float(line["speed"])
            passengerdata = [date, lat, lng, mac, rssi, speed]

            if mac not in tracker:
                tracker[mac] = {}
                tracker[mac][str(date)] = []
                tracker[mac][str(date)].append(passengerdata)
            else:
                if str(date) not in tracker[mac]:
                    tracker[mac][str(date)] = []

                tracker[mac][str(date)].append(passengerdata)

    # Summarize multiple beacon in the same second into a single beacon
    singletracker = {}
    freqtracker = {}
    for mac, beacons in tracker.items():
        singletracker[mac] = {}
        freqtracker[mac] = []

        for sentdate, sentbeacons in beacons.items():
            meanlat = np.mean([x[1] for x in sentbeacons])
            meanlng = np.mean([x[2] for x in sentbeacons])
            meanrssi = np.mean([x[4] for x in sentbeacons])
            meanspeed = np.mean([x[5] for x in sentbeacons])
            mindist = closest(meanlat, meanlng, stops)

            # Get the # of beacon in winsize
            freq = 0
            currentdate = sentbeacons[0][0]
            for prevdata in reversed(freqtracker[mac]):
                prevdatadate = prevdata[0]
                timediff = (currentdate - prevdatadate).total_seconds()
                if timediff <= winsize:
                    freq = freq + 1
                else:
                    break

            outdata = [currentdate, meanlat, meanlng, mac, meanrssi,
                       meanspeed, mindist, freq]
            singletracker[mac][sentdate] = outdata
            freqtracker[mac].append(outdata)


    return singletracker


def toarff(sentbeacon, clazz):
    out = ",".join(str(x) for x in sentbeacon[4:]) + ","
    if clazz == 0:
        out = out + "OUT"
    else:
        out = out + "IN"
    return out + "\n"

@click.command()
@click.option("--inlog",   default="uailog.csv", help="Input File")
@click.option("--instops", default="lane.csv",
              help="Bus stops (stations) file")
@click.option("--inclass", default=0,
              help="Data class (0 outside bus, 1 inside bus)")
@click.option("--winsize", default=300,
              help="Maximum time (window size) in seconds between beacons ")
@click.option("--outlog", default="uai.out.csv", help="Output File")
@click.option("--outarff", default="uai.out.arff", help="ARFF Output File")
def main(inlog, instops, inclass, winsize, outlog, outarff):
    # Config logging
    logging.basicConfig()
    logger = logging.getLogger("uaibus.uaipreprocess")
    logger.setLevel(logging.INFO)

    # Read and parse stations
    stops = getstops(instops)

    # Read and parse log files in tracker
    tracker = getlog(inlog, stops, winsize)

    # Output to outfile
    # Also plot in matplotlib
    x = []  # RSSI
    y = []  # Speed
    z = []  # Dist
    with open(outlog, 'w', newline='') as outputcsvfile, \
         open(outarff, 'w', newline='') as arfffile:
        outwriter = csv.writer(outputcsvfile)
        outwriter.writerow(["date", "lat", "lng", "mac", "rssi",
                            "speed", "dist", "freq", "clazz"])

        arfffile.write("@RELATION uaibus\n\n")
        arfffile.write("@ATTRIBUTE rssi NUMERIC\n")
        arfffile.write("@ATTRIBUTE speed NUMERIC\n")
        arfffile.write("@ATTRIBUTE dist NUMERIC\n")
        arfffile.write("@ATTRIBUTE freq NUMERIC\n")
        arfffile.write("@ATTRIBUTE clazz {IN, OUT}\n\n")
        arfffile.write("@DATA\n")

        for mac, beacons in tracker.items():
            for sentdate, sentbeacon in beacons.items():
                outwriter.writerow(sentbeacon + [inclass])
                arfffile.write(toarff(sentbeacon, inclass))
                # To Plot
                x = x + [sentbeacon[4]]  # RSSI
                y = y + [sentbeacon[5]]  # Speed
                z = z + [sentbeacon[6]]  # Dist

        outputcsvfile.flush()
        arfffile.flush()


    # Plot 3D
    fig = plt.figure()
    plt.rc('text', usetex=True)
    # plt.rc('font', family='serif')
    plt.rcParams['text.latex.unicode'] = True

    ax = Axes3D(fig)
    ax.scatter(x, y, z, alpha=0.2, label=r"Fora do Ônibus", c="C0")
    # ax.scatter3D(x, y, z, c=z, cmap='tab20c')
    ax.set_xlabel(r'RSSI (dB)')
    ax.set_ylabel(r'Velocidade (m/s)')
    ax.set_zlabel(r'Distância')
    ax.legend(loc=8, borderaxespad=1)
    ax.set_title(r'Dispersão dos pacotes $ProbeRequest$ dos passageiros')

    fig.savefig("test.png")
    plt.show()


if __name__ == "__main__":
    main()
