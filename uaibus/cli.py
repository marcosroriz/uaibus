# -*- coding: utf-8 -*-

"""Console script for uaibussrc."""
import sys
import click
from scapy.all import sniff
from uaibussrc import scapy_ex

@click.command()
def main(args=None):
    """Console script for uaibussrc."""
    click.echo("Replace this message by putting your code into "
               "uaibussrc.cli.main")
    click.echo("See click documentation at http://click.pocoo.org/")
    return 0


if __name__ == "__main__":
    sys.exit(main())  # pragma: no cover
