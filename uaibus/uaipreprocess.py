#!/bin/env python
# import pudb
# pu.db

import csv
import datetime
import logging
import click
import sys
import numpy as np
from collections import defaultdict
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


def parselog(logfile, stops, winsize):
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
                tracker[mac] = [passengerdata]
            else:
                tracker[mac].append(passengerdata)

    return tracker


def derivelog(rawtracker, stops, winsize):
    # Derive complex data from rawtracker into final tracker
    finaltracker = {}
    histtracker = {}

    for mac, sentbeacons in rawtracker.items():
        finaltracker[mac] = []
        histtracker[mac] = []

        for beacon in sentbeacons:
            date = beacon[0]
            lat = beacon[1]
            lng = beacon[2]
            rssi = beacon[4]
            speed = beacon[5]

            # Derived Data
            stopdist = closest(lat, lng, stops)  # Min Dist to a bus stop
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

            for prevdata in reversed(histtracker[mac]):
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

            # Complex output data for this beacon = raw + derived data
            outdata = [date, lat, lng, mac, rssi, speed,
                       stopdist, wintravdist, wintravtime, winfrequence,
                       totaltravdist, totaltravtime, totalfrequence]

            # Save output
            finaltracker[mac].append(outdata)
            histtracker[mac].append(outdata)

    return finaltracker


def toarff(sentbeacon, clazz):
    out = ",".join(str(x) for x in sentbeacon[4:]) + ","
    if clazz == 0:
        out = out + "OUT"
    else:
        out = out + "IN"
    return out + "\n"


def output(finaltracker, outlog, outarff, clazz):
    # Output to outlog and outarff
    # Also store statistics
    stat = defaultdict(list)

    with open(outlog, 'w', newline='') as outputcsvfile, \
         open(outarff, 'w', newline='') as arfffile:

        outwriter = csv.writer(outputcsvfile)
        outwriter.writerow(["date", "lat", "lng", "mac",
                            "rssi", "speed", "stopdist",
                            "wintravdist", "wintravtime", "winfrequence",
                            "totaltravdist", "totaltravtime", "totalfrequence",
                            "clazz"])

        arfffile.write("@RELATION uaibus\n\n")
        arfffile.write("@ATTRIBUTE rssi NUMERIC\n")
        arfffile.write("@ATTRIBUTE speed NUMERIC\n")
        arfffile.write("@ATTRIBUTE stopdist NUMERIC\n")
        arfffile.write("@ATTRIBUTE wintravdist NUMERIC\n")
        arfffile.write("@ATTRIBUTE wintravtime NUMERIC\n")
        arfffile.write("@ATTRIBUTE winfrequence NUMERIC\n")
        arfffile.write("@ATTRIBUTE totaltravdist NUMERIC\n")
        arfffile.write("@ATTRIBUTE totaltravtime NUMERIC\n")
        arfffile.write("@ATTRIBUTE totalfrequence NUMERIC\n")
        arfffile.write("@ATTRIBUTE clazz {IN, OUT}\n\n")
        arfffile.write("@DATA\n")

        for mac, sentbeacons in finaltracker.items():
            for beacon in sentbeacons:
                outwriter.writerow(beacon + [clazz])
                arfffile.write(toarff(beacon, clazz))

                # For Statistics
                stat['rssi'].append(beacon[4])
                stat['speed'].append(beacon[5])
                stat['stopdist'].append(beacon[6])
                stat['wintravdist'].append(beacon[7])
                stat['wintravtime'].append(beacon[8])
                stat['winfrequence'].append(beacon[9])
                stat['totaltravdist'].append(beacon[10])
                stat['totaltravtime'].append(beacon[11])
                stat['totalfrequence'].append(beacon[12])
                stat['clazz'].append(clazz)

        outputcsvfile.flush()
        arfffile.flush()

    return stat


def outplot(stat, legend, x, y, z, clazz):
    # Plot 3D
    fig = plt.figure()
    plt.rc('text', usetex=True)
    # plt.rc('font', family='serif')
    plt.rcParams['text.latex.unicode'] = True

    ax = Axes3D(fig)
    plabel = "Fora do Ônibus"
    if clazz == 1:
        plabel = "Dentro do Ônibus"

    ax.scatter(stat[x], stat[y], stat[z], alpha=0.2, label=plabel, c="C0")
    # ax.scatter3D(x, y, z, c=z, cmap='tab20c')
    ax.set_xlabel(legend[x])
    ax.set_ylabel(legend[y])
    ax.set_zlabel(legend[z])
    ax.legend(loc=8, borderaxespad=0)
    # leg.draggable(True)
    ax.set_title(r'Dispersão dos pacotes $ProbeRequest$ dos passageiros')
    fig.savefig("test.png")
    fig.tight_layout()
    fig.subplots_adjust(left=-0.11)
    plt.show()


@click.command()
@click.option("--inlog",   default="uailog.csv",    help="Input File")
@click.option("--outlog",  default="uai.out.csv",   help="Output File")
@click.option("--outarff", default="uai.out.arff",  help="ARFF Output File")
@click.option("--instops", default="lane.csv",
              help="Bus stops (stations) file")
@click.option("--clazz",   default=0,
              help="Data class (0 outside bus, 1 inside bus)")
@click.option("--winsize", default=120,
              help="Maximum time (window size) in seconds between beacons ")
@click.option("--x",       default="rssi",          help="X Variable (Plot)")
@click.option("--y",       default="totaltravtime", help="Y Variable (Plot)")
@click.option("--z",       default="totaltravdist", help="Z Variable (Plot)")
def main(inlog, instops, clazz, winsize, outlog, outarff, x, y, z):
    # Config logging
    logging.basicConfig()
    logger = logging.getLogger("uaibus.uaipreprocess")
    logger.setLevel(logging.INFO)

    # Read and parse stations
    stops = getstops(instops)

    # Read and parse basic variables in rawtracker
    rawtracker = parselog(inlog, stops, winsize)

    # Read and derive complex variables in the final tracker
    finaltracker = derivelog(rawtracker, stops, winsize)

    # Output to outfile and retrieve statistics
    stat = output(finaltracker, outlog, outarff, clazz)

    # Plot
    legend = {
        'rssi'           : r'RSSI (dB)',
        'speed'          : r'Velocidade do Ônibus (km/h)',
        'stopdist'       : r'Distância ao ponto de Ônibus mais próximo (m)',
        'wintravdist'    : r'Distância (m) entre beacons na janela ($\Delta$)',
        'wintravtime'    : r'Tempo entre beacons na janela (\Delta$) em (s)',
        'winfrequence'   : r'Número de beacons recebidos ($\Delta$)',
        'totaltravdist'  : r'Distância total percorrida pelo dispositivo (m)',
        'totaltravtime'  : r'Tempo total percorrido pelo dispositivo (s)',
        'totalfrequence' : r'Número total de beacons recebidos',
        'clazz'          : r'Classificação do beacon'
    }
    outplot(stat, legend, x, y, z, clazz)


if __name__ == "__main__":
    main()
