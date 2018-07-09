#!/bin/env python
# import pudb
# pu.db
import random
import csv
import logging
import click
import sys
from math import asin, atan2, cos, radians, sin, sqrt
import matplotlib.pyplot as plt
from mpl_toolkits.mplot3d import Axes3D


@click.command()
@click.option("--outsidecsv",  default="outside.csv", help="Outside signals")
@click.option("--insidecsv",   default="inside.csv",  help="Inside signals")
@click.option("--usesampling", default=False, is_flag=True, help="Use sampling?")
@click.option("--x", default="rssi", help="X Variable (Plot)")
@click.option("--y", default="winfrequence", help="Y Variable (Plot)")
@click.option("--z", default="wintravdist", help="Z Variable (Plot)")
def main(outsidecsv, insidecsv, usesampling, x, y, z):
    outfile = open(outsidecsv, "r")
    outfreader = csv.DictReader(outfile)

    infile = open(insidecsv, "r")
    infreader = csv.DictReader(infile)

    legend = {
        'rssi'           : r'RSSI (dB)',
        'speed'          : r'Velocidade do Ônibus (km/h)',
        'stopdist'       : r'Distância ao ponto de Ônibus mais próximo (m)',
        'wintravdist'    : r'Distância (m) entre beacons na janela ($\Delta$)',
        'wintravtime'    : r'Tempo entre beacons na janela ($\Delta$) em (s)',
        'winfrequence'   : r'Número de beacons recebidos ($\Delta$)',
        'totaltravdist'  : r'Distância total percorrida pelo dispositivo (m)',
        'totaltravtime'  : r'Tempo total percorrido pelo dispositivo (s)',
        'totalfrequence' : r'Número total de beacons recebidos',
        'clazz'          : r'Classificação do beacon'
    }

    outx = []
    outy = []
    outz = []
    for line in outfreader:
        if usesampling:
            prob = random.random()
            if prob <= 0.25:
                outx = outx + [float(line[x])]
                outy = outy + [float(line[y])]
                outz = outz + [float(line[z])]
        else:
            outx = outx + [float(line[x])]
            outy = outy + [float(line[y])]
            outz = outz + [float(line[z])]

    # In
    inx = []
    iny = []
    inz = []
    for line in infreader:
        if usesampling:
            prob = random.random()
            if prob <= 0.25:
                inx = inx + [float(line[x])]
                iny = iny + [float(line[y])]
                inz = inz + [float(line[z])]
        else:
            inx = inx + [float(line[x])]
            iny = iny + [float(line[y])]
            inz = inz + [float(line[z])]


    # Plot 3D
    fig = plt.figure()
    plt.rc('text', usetex=True)
    # plt.rc('font', family='serif')
    plt.rcParams['text.latex.unicode'] = True

    ax = Axes3D(fig)
    ax.scatter(outx, outy, outz, alpha=0.2, label=r"Fora do Ônibus", c="C0")
    ax.scatter(inx, iny, inz, alpha=0.2, label=r"Dentro do Ônibus", c="Red")
    # ax.scatter3D(x, y, z, c=z, cmap='tab20c')
    ax.set_xlabel(legend[x])
    ax.set_ylabel(legend[y])
    ax.set_zlabel(legend[z])
    ax.legend(loc=8)
    ax.set_title(r'Dispersão dos pacotes $ProbeRequest$ dos passageiros')

    fig.savefig("test.png")
    plt.show()


if __name__ == "__main__":
    main()
