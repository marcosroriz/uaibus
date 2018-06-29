#!/bin/env python
# import pudb
# pu.db

import csv
import logging
import click
import sys
from math import asin, atan2, cos, radians, sin, sqrt
import matplotlib.pyplot as plt
from mpl_toolkits.mplot3d import Axes3D


@click.command()
@click.option("--outsidecsv", default="outside.csv", help="Outside signals")
@click.option("--insidecsv",  default="inside.csv",  help="Inside signals")
def main(outsidecsv, insidecsv):
    # Config logging
    logging.basicConfig()
    logger = logging.getLogger("uaibus.compare")
    logger.setLevel(logging.INFO)

    outfile = open(outsidecsv, "r")
    outfreader = csv.DictReader(outfile)

    infile = open(insidecsv, "r")
    infreader = csv.DictReader(infile)

    # Out
    outx = []  # RSSI
    outy = []  # Total number of beacons in time window
    outz = []  # Travelled dist within time window
    for line in outfreader:
        rssi = float(line["rssi"])
        speed = float(line["speed"])
        stopdist = float(line["stopdist"])
        travdist = float(line["travdist"])
        uniqfreq = int(line["uniqfreq"])
        totalfreq = int(line["totalfreq"])

        # To Plot
        outx = outx + [rssi]   # RSSI
        outy = outy + [uniqfreq]  # Speed
        outz = outz + [totalfreq]   # Dist

    # In
    inx = []  # RSSI
    iny = []  # Speed
    inz = []  # Dist
    for line in infreader:
        rssi = float(line["rssi"])
        speed = float(line["speed"])
        stopdist = float(line["stopdist"])
        travdist = float(line["travdist"])
        uniqfreq = int(line["uniqfreq"])
        totalfreq = int(line["totalfreq"])

        # To Plot
        inx = inx + [rssi]   # RSSI
        iny = iny + [stopdist]  # Speed
        inz = inz + [travdist]   # Dist


    # Plot 3D
    fig = plt.figure()
    plt.rc('text', usetex=True)
    # plt.rc('font', family='serif')
    plt.rcParams['text.latex.unicode'] = True

    ax = Axes3D(fig)
    ax.scatter(outx, outy, outz, alpha=0.2, label=r"Fora do Ônibus", c="C0")
    ax.scatter(inx, iny, inz, alpha=0.2, label=r"Dentro do Ônibus", c="Red")
    # ax.scatter3D(x, y, z, c=z, cmap='tab20c')
    ax.set_xlabel(r'RSSI (dB)')
    ax.set_ylabel(r'Velocidade (m/s)')
    ax.set_zlabel(r'Distância')
    ax.legend(loc=8)
    ax.set_title(r'Dispersão dos pacotes $ProbeRequest$ dos passageiros')

    fig.savefig("test.png")
    plt.show()


if __name__ == "__main__":
    main()
