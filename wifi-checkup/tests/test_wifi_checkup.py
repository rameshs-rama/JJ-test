"""Tests for wifi_checkup.py.

Run from the wifi-checkup folder with:  python3 -m unittest discover -s tests -v

The fixtures below are samples of what each operating system's own tools print,
so the parsers can be checked on any computer.
"""

import http.server
import json
import os
import socket
import socketserver
import struct
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

# Local test servers must never be reached through a proxy.
os.environ["NO_PROXY"] = os.environ["no_proxy"] = "127.0.0.1,localhost"

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import wifi_checkup as wc  # noqa: E402


# --------------------------------------------------------------------------
# Fixtures: real-world command output
# --------------------------------------------------------------------------

NETSH_INTERFACES = """
There is 1 interface on the system:

    Name                   : Wi-Fi
    Description            : Intel(R) Wi-Fi 6 AX201 160MHz
    GUID                   : 3f7c0b8e-1234-4a5b-9c8d-0e1f2a3b4c5d
    Physical address       : 4c:79:6e:12:34:56
    Interface type         : Primary
    State                  : connected
    SSID                   : HomeNet
    AP BSSID               : a0:b1:c2:d3:e4:f5
    Band                   : 5 GHz
    Channel                : 44
    Connected Akm-cipher   : [ akm = 00-0f-ac:02, cipher = 00-0f-ac:04 ]
    Network type           : Infrastructure
    Radio type             : 802.11ax
    Authentication         : WPA2-Personal
    Cipher                 : CCMP
    Connection mode        : Auto Connect
    Receive rate (Mbps)    : 1201
    Transmit rate (Mbps)   : 960.5
    Signal                 : 92%
    Profile                : HomeNet
    QoS MSCS Configured         : 0

    Hosted network status  : Not available
"""

NETSH_INTERFACES_WIN10 = """
There is 1 interface on the system:

    Name                   : Wi-Fi
    Description            : Realtek RTL8821CE 802.11ac PCIe Adapter
    GUID                   : 11111111-2222-3333-4444-555555555555
    Physical address       : 74:12:b3:aa:bb:cc
    State                  : connected
    SSID                   : Flat 4B
    BSSID                  : 10:20:30:40:50:60
    Network type           : Infrastructure
    Radio type             : 802.11n
    Authentication         : WPA-Personal
    Cipher                 : TKIP
    Connection mode        : Profile
    Channel                : 9
    Receive rate (Mbps)    : 72.2
    Transmit rate (Mbps)   : 72.2
    Signal                 : 38%
    Profile                : Flat 4B
"""

NETSH_LOCATION_DENIED = """Network shell commands need location permission to access WLAN information. Turn on Location services on the Location page in Privacy & security settings.

Here is the URI for the Location page in the Settings app:
ms-settings:privacy-location
"""

NETSH_GERMAN = """
Es ist 1 Schnittstelle auf dem System vorhanden:

    Name                   : WLAN
    Beschreibung           : Intel(R) Wi-Fi 6 AX201 160MHz
    Physische Adresse      : 4c:79:6e:12:34:56
    Status                 : Verbunden
    SSID                   : HomeNet
    Funktyp                : 802.11ac
    Signal                 : 81%
"""

NETSH_NETWORKS = """
Interface name : Wi-Fi
There are 3 networks currently visible.

SSID 1 : HomeNet
    Network type            : Infrastructure
    Authentication          : WPA2-Personal
    Encryption              : CCMP
    BSSID 1                 : a0:b1:c2:d3:e4:f5
         Signal             : 92%
         Radio type         : 802.11ax
         Band               : 5 GHz
         Channel            : 44
         Bss Load:
             Connected Stations:        3
             Channel Utilization:       25 (9 %)
         Basic rates (Mbps) : 6 12 24
    BSSID 2                 : a0:b1:c2:d3:e4:f4
         Signal             : 99%
         Radio type         : 802.11ax
         Band               : 2.4 GHz
         Channel            : 6
         Basic rates (Mbps) : 1 2 5.5 11

SSID 2 : Neighbour_2G
    Network type            : Infrastructure
    Authentication          : WPA2-Personal
    Encryption              : CCMP
    BSSID 1                 : 11:22:33:44:55:66
         Signal             : 60%
         Radio type         : 802.11n
         Band               : 2.4 GHz
         Channel            : 6

SSID 3 :
    Network type            : Infrastructure
    Authentication          : Open
    Encryption              : None
    BSSID 1                 : 22:33:44:55:66:77
         Signal             : 30%
         Radio type         : 802.11n
         Channel            : 3
"""

SYSTEM_PROFILER = """Wi-Fi:

      Software Versions:
          CoreWLAN: 16.0 (1657)
          IO80211 Family: 12.0 (1200.13.1)
      Interfaces:
        en0:
          Card Type: Wi-Fi  (0x14E4, 0x4387)
          Firmware Version: wl0: Mar 29 2024 14:41:55 version 20.10.1066 FWID 01-ac3bf8b3
          MAC Address: f0:2f:4b:aa:bb:cc
          Locale: FCC
          Country Code: IN
          Supported PHY Modes: 802.11 a/b/g/n/ac/ax
          Supported Channels: 1 (2GHz), 2 (2GHz), 36 (5GHz, 20MHz)
          Wake On Wireless: Supported
          Status: Connected
          Current Network Information:
            HomeNet:
              PHY Mode: 802.11ac
              Channel: 149 (5GHz, 80MHz)
              Country Code: IN
              Network Type: Infrastructure
              Security: WPA2 Personal
              Signal / Noise: -71 dBm / -90 dBm
              Transmit Rate: 234
              MCS Index: 5
          Other Local Wi-Fi Networks:
            HomeNet:
              PHY Mode: 802.11
              Channel: 1 (2GHz, 20MHz)
              Network Type: Infrastructure
              Security: WPA2 Personal
              Signal / Noise: -50 dBm / -92 dBm
            Neighbour:
              PHY Mode: 802.11
              Channel: 149 (5GHz, 80MHz)
              Network Type: Infrastructure
              Security: WPA2 Personal
              Signal / Noise: -65 dBm / -92 dBm
            Cafe:
              PHY Mode: 802.11
              Channel: 6 (2GHz, 20MHz)
              Network Type: Infrastructure
              Security: None
              Signal / Noise: -80 dBm / -92 dBm
        awdl0:
          MAC Address: 2a:bb:cc:dd:ee:ff
          Supported PHY Modes: 802.11 a/b/g/n/ac/ax
          Status: Inactive
"""

AIRPORT_I = """     agrCtlRSSI: -52
     agrExtRSSI: 0
    agrCtlNoise: -92
    agrExtNoise: 0
          state: running
        op mode: station
     lastTxRate: 867
        maxRate: 867
lastAssocStatus: 0
    802.11 auth: open
      link auth: wpa2-psk
          BSSID: a0:b1:c2:d3:e4:f5
           SSID: HomeNet
            MCS: 9
        channel: 44,80
"""

IW_LINK = """Connected to a0:b1:c2:d3:e4:f5 (on wlan0)
\tSSID: HomeNet
\tfreq: 5220
\tRX: 123456 bytes (789 packets)
\tTX: 23456 bytes (123 packets)
\tsignal: -56 dBm
\trx bitrate: 866.7 MBit/s VHT-MCS 9 80MHz short GI VHT-NSS 2
\ttx bitrate: 780.0 MBit/s VHT-MCS 8 80MHz short GI VHT-NSS 2

\tbss flags:\tshort-slot-time
\tdtim period:\t1
"""

NMCLI = """ :Neighbour:11\\:22\\:33\\:44\\:55\\:66:6:2437 MHz:130 Mbit/s:65:WPA2
*:HomeNet:A0\\:B1\\:C2\\:D3\\:E4\\:F5:44:5220 MHz:540 Mbit/s:78:WPA2 WPA3
 :HomeNet:A0\\:B1\\:C2\\:D3\\:E4\\:F4:6:2437 MHz:195 Mbit/s:90:WPA2 WPA3
 :Open Cafe:22\\:33\\:44\\:55\\:66\\:77:11:2462 MHz:54 Mbit/s:30:
 :Wi\\:Fi 6E:33\\:44\\:55\\:66\\:77\\:88:37:6135 MHz:1201 Mbit/s:40:WPA3
"""

PROC_WIRELESS = """Inter-| sta-|   Quality        |   Discarded packets               | Missed | WE
 face | tus | link level noise |  nwid  crypt   frag  retry   misc | beacon | 22
wlan0: 0000   54.  -56.  -256        0      0      0      0     34        0
"""

PING_LINUX = """PING 1.1.1.1 (1.1.1.1) 56(84) bytes of data.
64 bytes from 1.1.1.1: icmp_seq=1 ttl=57 time=12.3 ms
64 bytes from 1.1.1.1: icmp_seq=2 ttl=57 time=14.1 ms
64 bytes from 1.1.1.1: icmp_seq=2 ttl=57 time=14.3 ms (DUP!)
64 bytes from 1.1.1.1: icmp_seq=4 ttl=57 time=11.9 ms

--- 1.1.1.1 ping statistics ---
4 packets transmitted, 3 received, +1 duplicates, 25% packet loss, time 3004ms
rtt min/avg/max/mdev = 11.900/12.766/14.100/0.960 ms
"""

PING_WINDOWS = """
Pinging 192.168.1.1 with 32 bytes of data:
Reply from 192.168.1.1: bytes=32 time=3ms TTL=64
Reply from 192.168.1.1: bytes=32 time<1ms TTL=64
Request timed out.
Reply from 192.168.1.23: Destination host unreachable.

Ping statistics for 192.168.1.1:
    Packets: Sent = 4, Received = 3, Lost = 1 (25% loss),
Approximate round trip times in milli-seconds:
    Minimum = 0ms, Maximum = 3ms, Average = 1ms
"""

PING_WINDOWS_GERMAN = """
Ping wird ausgefuehrt fuer 1.1.1.1 mit 32 Bytes Daten:
Antwort von 1.1.1.1: Bytes=32 Zeit=15ms TTL=57
Antwort von 1.1.1.1: Bytes=32 Zeit=14ms TTL=57

Ping-Statistik fuer 1.1.1.1:
    Pakete: Gesendet = 2, Empfangen = 2, Verloren = 0
    Minimum = 14ms, Maximum = 15ms, Mittelwert = 14ms
"""

PING_FRENCH = "Reponse de 1.1.1.1 : octets=32 temps=12 ms TTL=57\n"

PING_MAC = """PING 1.1.1.1 (1.1.1.1): 56 data bytes
64 bytes from 1.1.1.1: icmp_seq=0 ttl=57 time=12.345 ms
Request timeout for icmp_seq 1
64 bytes from 1.1.1.1: icmp_seq=2 ttl=57 time=13.001 ms

--- 1.1.1.1 ping statistics ---
3 packets transmitted, 2 packets received, 33.3% packet loss
round-trip min/avg/max/stddev = 12.345/12.673/13.001/0.328 ms
"""

ROUTE_PRINT = """===========================================================================
Interface List
 12...4c 79 6e 12 34 56 ......Intel(R) Wi-Fi 6 AX201 160MHz
  1...........................Software Loopback Interface 1
===========================================================================

IPv4 Route Table
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0         10.8.0.1        10.8.0.5    100
          0.0.0.0          0.0.0.0      192.168.1.1    192.168.1.23     35
===========================================================================
Persistent Routes:
  Network Address          Netmask  Gateway Address  Metric
          0.0.0.0          0.0.0.0      192.168.1.1  Default
===========================================================================
"""

ROUTE_GET = """   route to: default
destination: default
       mask: default
    gateway: 192.168.1.1
  interface: en0
      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>
 recvpipe  sendpipe  ssthresh  rtt,msec    rttvar  hopcount      mtu     expire
       0         0         0         0         0         0      1500         0
"""

IP_ROUTE = """default via 192.168.1.1 dev wlan0 proto dhcp src 192.168.1.23 metric 600
default via 192.168.1.1 dev eth0 proto dhcp src 192.168.1.30 metric 100
"""

PROC_ROUTE = """Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT
wlan0\t00000000\t0101A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0
wlan0\t0001A8C0\t00000000\t0001\t0\t0\t600\t00FFFFFF\t0\t0\t0
"""

IP_ADDR = """1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever preferred_lft forever
3: wlan0    inet 192.168.1.23/24 brd 192.168.1.255 scope global dynamic noprefixroute wlan0\\       valid_lft 85000sec
"""

IFCONFIG = """lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384
\tinet 127.0.0.1 netmask 0xff000000
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\toptions=6460<TSO4,TSO6,CHANNEL_IO,PARTIAL_CSUM,ZEROINVERT_CSUM>
\tether 3a:1b:2c:3d:4e:5f
\tinet6 fe80::1c2b:3a4d:5e6f:7a8b%en0 prefixlen 64 secured scopeid 0xb
\tinet 192.168.1.23 netmask 0xffffff00 broadcast 192.168.1.255
\tstatus: active
"""

IPCONFIG = """
Windows IP Configuration


Wireless LAN adapter Wi-Fi:

   Connection-specific DNS Suffix  . : home
   Link-local IPv6 Address . . . . . : fe80::1234:5678:9abc:def0%12
   IPv4 Address. . . . . . . . . . . : 192.168.1.23
   Subnet Mask . . . . . . . . . . . : 255.255.252.0
   Default Gateway . . . . . . . . . : 192.168.1.1
"""

ARP_WINDOWS = """
Interface: 192.168.1.23 --- 0xc
  Internet Address      Physical Address      Type
  192.168.1.1           a0-b1-c2-d3-e4-f5     dynamic
  192.168.1.40          da-a1-19-00-11-22     dynamic
  192.168.1.255         ff-ff-ff-ff-ff-ff     static
  224.0.0.22            01-00-5e-00-00-16     static
  239.255.255.250       01-00-5e-7f-ff-fa     static
"""

ARP_MAC = """? (192.168.1.1) at a0:b1:c2:d3:e4:f5 on en0 ifscope [ethernet]
? (192.168.1.40) at da:a1:19:0:11:22 on en0 ifscope [ethernet]
? (192.168.1.77) at (incomplete) on en0 ifscope [ethernet]
? (192.168.1.255) at ff:ff:ff:ff:ff:ff on en0 ifscope [ethernet]
? (224.0.0.251) at 1:0:5e:0:0:fb on en0 ifscope permanent [ethernet]
"""

PROC_ARP = """IP address       HW type     Flags       HW address            Mask     Device
192.168.1.1      0x1         0x2         a0:b1:c2:d3:e4:f5     *        wlan0
192.168.1.40     0x1         0x2         da:a1:19:00:11:22     *        wlan0
192.168.1.77     0x1         0x0         00:00:00:00:00:00     *        wlan0
"""

UPNP_XML = b"""<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
  <device>
    <deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
    <friendlyName>Archer C6 &amp; Co</friendlyName>
    <manufacturer>TP-Link</manufacturer>
    <modelName>Archer C6</modelName>
    <modelNumber>2.0</modelNumber>
    <deviceList><device><friendlyName>WANDevice</friendlyName></device></deviceList>
  </device>
</root>"""


# --------------------------------------------------------------------------
# Parser tests
# --------------------------------------------------------------------------

class WindowsParsers(unittest.TestCase):
    def test_interfaces(self):
        info = wc.finalize_wifi(wc.parse_netsh_interfaces(NETSH_INTERFACES))
        self.assertEqual(info["ssid"], "HomeNet")
        self.assertEqual(info["bssid"], "a0:b1:c2:d3:e4:f5")
        self.assertEqual(info["mac"], "4c:79:6e:12:34:56")
        self.assertEqual(info["channel"], 44)
        self.assertEqual(info["band"], "5 GHz")
        self.assertEqual(info["signal_pct"], 92)
        self.assertEqual(info["rssi"], -54)
        self.assertTrue(info["rssi_estimated"])
        self.assertEqual(info["rx_rate"], 1201)
        self.assertEqual(info["tx_rate"], 960.5)
        self.assertEqual(info["generation"], "Wi-Fi 6")
        self.assertEqual(info["security_level"], "good")
        self.assertTrue(info["connected"])

    def test_interfaces_windows10_old_security(self):
        info = wc.finalize_wifi(wc.parse_netsh_interfaces(NETSH_INTERFACES_WIN10))
        self.assertEqual(info["ssid"], "Flat 4B")
        self.assertEqual(info["bssid"], "10:20:30:40:50:60")
        self.assertEqual(info["band"], "2.4 GHz")  # derived from channel 9
        self.assertEqual(info["security_level"], "weak")
        self.assertEqual(info["generation"], "Wi-Fi 4")
        self.assertEqual(info["rssi"], -81)

    def test_location_permission(self):
        info = wc.finalize_wifi(wc.parse_netsh_interfaces(NETSH_LOCATION_DENIED))
        self.assertIn("Location", info["note"])
        self.assertFalse(info["connected"])

    def test_german_fallbacks(self):
        info = wc.parse_netsh_interfaces(NETSH_GERMAN)
        self.assertEqual(info["ssid"], "HomeNet")
        self.assertEqual(info["signal_pct"], 81)
        self.assertEqual(info["standard"], "802.11ac")

    def test_empty_output(self):
        self.assertIn("netsh", wc.parse_netsh_interfaces("")["note"])

    def test_networks(self):
        nets = [wc.finalize_wifi(n) for n in wc.parse_netsh_networks(NETSH_NETWORKS)]
        self.assertEqual(len(nets), 4)
        self.assertEqual(nets[0]["ssid"], "HomeNet")
        self.assertEqual(nets[0]["channel"], 44)
        self.assertEqual(nets[1]["band"], "2.4 GHz")
        self.assertEqual(nets[2]["ssid"], "Neighbour_2G")
        self.assertEqual(nets[2]["signal_pct"], 60)
        self.assertEqual(nets[3]["ssid"], "")
        self.assertEqual(nets[3]["band"], "2.4 GHz")
        self.assertEqual(nets[3]["security_level"], "critical")

    def test_route_print_picks_lowest_metric(self):
        self.assertEqual(wc.parse_route_print(ROUTE_PRINT), ("192.168.1.1", "192.168.1.23"))

    def test_ipconfig_prefix(self):
        self.assertEqual(wc.parse_ipconfig_prefix(IPCONFIG, "192.168.1.23"), 22)
        self.assertIsNone(wc.parse_ipconfig_prefix(IPCONFIG, "192.168.1.2"))

    def test_powershell_prefix(self):
        text = "127.0.0.1/8\r\n192.168.1.23/24\r\n169.254.10.2/16\r\n"
        self.assertEqual(wc.parse_ps_prefix(text, "192.168.1.23"), 24)

    def test_arp(self):
        self.assertEqual(wc.parse_neighbor_table(ARP_WINDOWS),
                         [("192.168.1.1", "a0:b1:c2:d3:e4:f5"), ("192.168.1.40", "da:a1:19:00:11:22")])


class MacParsers(unittest.TestCase):
    def test_system_profiler(self):
        info, nearby = wc.parse_system_profiler(SYSTEM_PROFILER)
        wc.finalize_wifi(info)
        self.assertEqual(info["interface"], "en0")
        self.assertEqual(info["hw_mac"], "f0:2f:4b:aa:bb:cc")
        self.assertEqual(info["ssid"], "HomeNet")
        self.assertEqual(info["channel"], 149)
        self.assertEqual(info["band"], "5 GHz")
        self.assertEqual(info["width_mhz"], 80)
        self.assertEqual(info["rssi"], -71)
        self.assertEqual(info["noise"], -90)
        self.assertEqual(info["tx_rate"], 234)
        self.assertEqual(info["generation"], "Wi-Fi 5")
        self.assertEqual(info["security_level"], "good")
        self.assertTrue(info["connected"])
        self.assertEqual([n["ssid"] for n in nearby], ["HomeNet", "Neighbour", "Cafe"])
        self.assertEqual(nearby[0]["band"], "2.4 GHz")
        self.assertEqual(nearby[2]["rssi"], -80)
        self.assertEqual(wc.finalize_wifi(nearby[2])["security_level"], "critical")

    def test_redacted_name(self):
        text = SYSTEM_PROFILER.replace("            HomeNet:\n              PHY Mode: 802.11ac",
                                       "            <redacted>:\n              PHY Mode: 802.11ac")
        info, _ = wc.parse_system_profiler(text)
        self.assertIsNone(info["ssid"])
        self.assertTrue(info["ssid_hidden_by_os"])
        self.assertEqual(info["rssi"], -71)

    def test_not_connected(self):
        text = SYSTEM_PROFILER.split("          Current Network Information:")[0]
        info, nearby = wc.parse_system_profiler(text)
        self.assertEqual(info, {})
        self.assertEqual(nearby, [])

    def test_airport(self):
        info = wc.finalize_wifi(wc.parse_airport_info(AIRPORT_I))
        self.assertEqual(info["ssid"], "HomeNet")
        self.assertEqual(info["rssi"], -52)
        self.assertEqual(info["channel"], 44)
        self.assertEqual(info["band"], "5 GHz")
        self.assertEqual(info["security_level"], "good")

    def test_route_get(self):
        self.assertEqual(wc.parse_route_get(ROUTE_GET), ("192.168.1.1", "en0"))

    def test_ifconfig(self):
        self.assertEqual(wc.parse_ifconfig_prefix(IFCONFIG, "192.168.1.23"), 24)
        self.assertEqual(wc.parse_ifconfig_ether(IFCONFIG), "3a:1b:2c:3d:4e:5f")

    def test_arp(self):
        self.assertEqual(wc.parse_neighbor_table(ARP_MAC),
                         [("192.168.1.1", "a0:b1:c2:d3:e4:f5"), ("192.168.1.40", "da:a1:19:00:11:22")])


class LinuxParsers(unittest.TestCase):
    def test_iw_link(self):
        info = wc.finalize_wifi(wc.parse_iw_link(IW_LINK))
        self.assertEqual(info["ssid"], "HomeNet")
        self.assertEqual(info["bssid"], "a0:b1:c2:d3:e4:f5")
        self.assertEqual((info["channel"], info["band"]), (44, "5 GHz"))
        self.assertEqual(info["rssi"], -56)
        self.assertEqual(info["rx_rate"], 866.7)
        self.assertEqual(info["tx_rate"], 780.0)
        self.assertEqual(info["standard"], "802.11ac")
        self.assertEqual(info["width_mhz"], 80)

    def test_iw_not_connected(self):
        self.assertEqual(wc.parse_iw_link("Not connected.\n"), {})

    def test_nmcli(self):
        nets = wc.parse_nmcli_wifi(NMCLI)
        self.assertEqual(len(nets), 5)
        active = [n for n in nets if n["in_use"]]
        self.assertEqual(len(active), 1)
        self.assertEqual(active[0]["bssid"], "a0:b1:c2:d3:e4:f5")
        self.assertEqual((active[0]["channel"], active[0]["band"]), (44, "5 GHz"))
        self.assertEqual(wc.classify_security(active[0]["security"])[0], "strong")
        self.assertEqual(nets[3]["security"], "Open")
        self.assertEqual(nets[4]["ssid"], "Wi:Fi 6E")
        self.assertEqual((nets[4]["channel"], nets[4]["band"]), (37, "6 GHz"))

    def test_proc_wireless(self):
        self.assertEqual(wc.parse_proc_wireless(PROC_WIRELESS, "wlan0"), -56)
        self.assertIsNone(wc.parse_proc_wireless(PROC_WIRELESS, "wlan1"))

    def test_routes(self):
        self.assertEqual(wc.parse_ip_route(IP_ROUTE), ("192.168.1.1", "eth0"))
        self.assertEqual(wc.parse_proc_route(PROC_ROUTE), ("192.168.1.1", "wlan0"))

    def test_ip_addr(self):
        self.assertEqual(wc.parse_ip_addr_prefix(IP_ADDR, "192.168.1.23"), 24)
        self.assertEqual(wc.parse_ip_addr_iface(IP_ADDR, "192.168.1.23"), "wlan0")
        self.assertIsNone(wc.parse_ip_addr_prefix(IP_ADDR, "192.168.1.2"))

    def test_arp(self):
        self.assertEqual(wc.parse_neighbor_table(PROC_ARP),
                         [("192.168.1.1", "a0:b1:c2:d3:e4:f5"), ("192.168.1.40", "da:a1:19:00:11:22")])


class PingParsing(unittest.TestCase):
    def test_linux_ignores_duplicates_and_summary(self):
        self.assertEqual(wc.parse_ping_times(PING_LINUX), [12.3, 14.1, 11.9])

    def test_windows(self):
        self.assertEqual(wc.parse_ping_times(PING_WINDOWS), [3.0, 0.5])

    def test_translated_windows(self):
        self.assertEqual(wc.parse_ping_times(PING_WINDOWS_GERMAN), [15.0, 14.0])
        self.assertEqual(wc.parse_ping_times(PING_FRENCH), [12.0])

    def test_mac(self):
        self.assertEqual(wc.parse_ping_times(PING_MAC), [12.345, 13.001])

    def test_summary(self):
        s = wc.summarize_times([10.0, 12.0, 11.0, 30.0], 5)
        self.assertEqual(s["received"], 4)
        self.assertEqual(s["loss_pct"], 20.0)
        self.assertEqual(s["median_ms"], 11.5)
        self.assertEqual(s["jitter_ms"], round((2 + 1 + 19) / 3, 1))
        empty = wc.summarize_times([], 10)
        self.assertEqual((empty["received"], empty["loss_pct"]), (0, 100.0))
        self.assertNotIn("median_ms", empty)


class Helpers(unittest.TestCase):
    def test_norm_mac(self):
        self.assertEqual(wc.norm_mac("A0-B1-C2-D3-E4-F5"), "a0:b1:c2:d3:e4:f5")
        self.assertEqual(wc.norm_mac("a0:b1:c:d3:e4:5"), "a0:b1:0c:d3:e4:05")
        self.assertIsNone(wc.norm_mac("a0:b1:c2:d3:e4"))
        self.assertIsNone(wc.norm_mac("zz:b1:c2:d3:e4:f5"))
        self.assertIsNone(wc.norm_mac(None))

    def test_mac_kinds(self):
        self.assertTrue(wc.is_random_mac("da:a1:19:00:11:22"))
        self.assertFalse(wc.is_random_mac("a0:b1:c2:d3:e4:f5"))
        self.assertFalse(wc.is_unicast_mac("01:00:5e:00:00:16"))
        self.assertFalse(wc.is_unicast_mac("ff:ff:ff:ff:ff:ff"))

    def test_masks(self):
        self.assertEqual(wc.mask_to_prefix("255.255.255.0"), 24)
        self.assertEqual(wc.mask_to_prefix("0xffffff00"), 24)
        self.assertEqual(wc.mask_to_prefix("255.255.254.0"), 23)
        self.assertIsNone(wc.mask_to_prefix("255.0.255.0"))

    def test_frequencies(self):
        self.assertEqual(wc.freq_to_channel(2412), (1, "2.4 GHz"))
        self.assertEqual(wc.freq_to_channel(2484), (14, "2.4 GHz"))
        self.assertEqual(wc.freq_to_channel(5180), (36, "5 GHz"))
        self.assertEqual(wc.freq_to_channel(5825), (165, "5 GHz"))
        self.assertEqual(wc.freq_to_channel(5955), (1, "6 GHz"))

    def test_security(self):
        cases = {("WPA2-Personal", "CCMP"): "good", ("WPA3-Personal", "GCMP"): "strong",
                 ("WPA2/WPA3 Personal", None): "strong", ("WPA2-Enterprise", None): "strong",
                 ("Open", "None"): "critical", ("None", None): "critical", ("WEP", None): "critical",
                 ("WPA-Personal", "TKIP"): "weak", ("WPA2-Personal", "TKIP"): "weak",
                 ("OWE", "CCMP"): "fair", ("wpa2-psk", None): "good", ("", None): "unknown"}
        for (sec, cipher), level in cases.items():
            self.assertEqual(wc.classify_security(sec, cipher)[0], level, (sec, cipher))

    def test_generation(self):
        self.assertEqual(wc.wifi_generation("802.11ax", "6 GHz"), "Wi-Fi 6E")
        self.assertEqual(wc.wifi_generation("802.11be"), "Wi-Fi 7")
        self.assertEqual(wc.wifi_generation("802.11g"), "older than Wi-Fi 4")
        self.assertIsNone(wc.wifi_generation(None))

    def test_signal_labels(self):
        self.assertEqual([wc.signal_label(x) for x in (-45, -63, -70, -82)],
                         ["Strong", "Good", "Fair", "Weak"])


class ChannelAnalysis(unittest.TestCase):
    def test_24ghz(self):
        wifi = {"ssid": "HomeNet", "bssid": "aa:aa:aa:aa:aa:01", "band": "2.4 GHz", "channel": 6}
        nearby = [
            {"ssid": "A", "bssid": "01:00:00:00:00:01", "band": "2.4 GHz", "channel": 6, "rssi": -55},
            {"ssid": "B", "bssid": "01:00:00:00:00:02", "band": "2.4 GHz", "channel": 7, "rssi": -58},
            {"ssid": "C", "bssid": "01:00:00:00:00:03", "band": "2.4 GHz", "channel": 1, "rssi": -85},
            {"ssid": "HomeNet", "bssid": "aa:aa:aa:aa:aa:02", "band": "5 GHz", "channel": 44, "rssi": -50},
        ]
        r = wc.analyze_channels(wifi, nearby)
        self.assertEqual(r["counts_24"], {1: 1, 6: 2, 11: 1})
        self.assertEqual(r["best_24"], 1)
        self.assertEqual(r["overlapping"], 2)
        self.assertEqual(r["own_score"], 4.0)
        self.assertEqual(r["own_on_other_bands"], ["5 GHz"])

    def test_5ghz(self):
        wifi = {"ssid": "HomeNet", "band": "5 GHz", "channel": 36}
        nearby = [{"ssid": x, "band": "5 GHz", "channel": 36, "rssi": -60} for x in "ABC"]
        r = wc.analyze_channels(wifi, nearby)
        self.assertEqual((r["same_channel"], r["same_channel_strong"]), (3, 3))


# --------------------------------------------------------------------------
# DNS, mDNS, NetBIOS and UPnP packets
# --------------------------------------------------------------------------

def _encode_name(name):
    return b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"


class FakeUDPServer(threading.Thread):
    """Answers each UDP query with reply_fn(query) (or not at all if it returns None)."""

    def __init__(self, reply_fn):
        super().__init__(daemon=True)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.reply_fn = reply_fn
        self.sock.settimeout(0.2)
        self.stop = False
        self.start()

    def run(self):
        while not self.stop:
            try:
                data, addr = self.sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                return
            reply = self.reply_fn(data)
            if reply:
                self.sock.sendto(reply, addr)

    def close(self):
        self.stop = True
        self.join(1)
        self.sock.close()


def dns_reply(query, answers, rcode=0):
    """Build a reply that echoes the question and points answer names back at it (compression)."""
    tid = query[:2]
    question = query[12:]
    header = tid + struct.pack(">HHHHH", 0x8180 | rcode, 1, len(answers), 0, 0)
    body = b""
    for rtype, rdata in answers:
        body += b"\xc0\x0c" + struct.pack(">HHIH", rtype, 1, 60, len(rdata)) + rdata
    return header + question + body


class DnsTests(unittest.TestCase):
    def test_query_packet(self):
        tid, pkt = wc.build_dns_query("example.com", tid=0x1234)
        self.assertEqual(pkt[:2], b"\x12\x34")
        self.assertEqual(pkt[12:], _encode_name("example.com") + b"\x00\x01\x00\x01")

    def test_a_record_roundtrip_and_timing(self):
        srv = FakeUDPServer(lambda q: dns_reply(q, [(1, socket.inet_aton("93.184.216.34"))]))
        try:
            ms, parsed = wc.dns_query("127.0.0.1", "example.com", port=srv.port, timeout=2)
            self.assertIsNotNone(ms)
            self.assertLess(ms, 1000)
            self.assertEqual(parsed["rcode"], 0)
            self.assertEqual(parsed["answers"], [("A", "93.184.216.34")])
        finally:
            srv.close()

    def test_ptr_with_compression(self):
        def reply(q):
            # PTR target "Phone.local" where "local" is itself a pointer to a later label
            return dns_reply(q, [(12, b"\x05Phone\xc0\x0c")])
        srv = FakeUDPServer(reply)
        try:
            ms, parsed = wc.dns_query("127.0.0.1", "local", qtype=12, port=srv.port, timeout=2,
                                      recursion=False)
            self.assertEqual(parsed["answers"], [("PTR", "Phone.local")])
        finally:
            srv.close()

    def test_wrong_id_is_ignored_then_times_out(self):
        srv = FakeUDPServer(lambda q: b"\x00\x00" + dns_reply(q, [])[2:] if q[:2] != b"\x00\x00" else None)
        try:
            t0 = time.perf_counter()
            ms, parsed = wc.dns_query("127.0.0.1", "example.com", port=srv.port, timeout=0.5)
            self.assertIsNone(ms)
            self.assertLess(time.perf_counter() - t0, 1.5)
        finally:
            srv.close()

    def test_no_server(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        self.assertEqual(wc.dns_query("127.0.0.1", "example.com", port=port, timeout=0.5), (None, None))

    def test_pointer_loop_is_rejected(self):
        msg = b"\x00" * 12 + b"\xc0\x0c"
        with self.assertRaises(ValueError):
            wc.read_dns_name(msg, 12)

    def test_server_speed_summary(self):
        srv = FakeUDPServer(lambda q: dns_reply(q, [(1, b"\x01\x02\x03\x04")]))
        try:
            orig = wc.dns_query
            wc.dns_query = lambda server, name, **kw: orig(server, name, port=srv.port, timeout=1)
            res = wc.dns_server_speed("127.0.0.1", ["a.com", "b.com", "c.com"])
            self.assertEqual((res["answered"], res["failed"]), (3, 0))
            self.assertIsNotNone(res["median_ms"])
        finally:
            wc.dns_query = orig
            srv.close()


class NetbiosTests(unittest.TestCase):
    def test_parse_node_status(self):
        def entry(name, suffix, flags):
            return name.ljust(15).encode() + bytes([suffix]) + struct.pack(">H", flags)
        names = entry("WORKGROUP", 0x00, 0x8400) + entry("LAPTOP-RS", 0x00, 0x0400) + entry("LAPTOP-RS", 0x20, 0x0400)
        rdata = bytes([3]) + names + b"\x00" * 6
        msg = (struct.pack(">HHHHHH", 1, 0x8400, 0, 1, 0, 0) + wc.NBSTAT_NAME +
               struct.pack(">HHIH", 0x21, 1, 0, len(rdata)) + rdata)
        self.assertEqual(wc.parse_nbstat(msg), "LAPTOP-RS")

    def test_garbage(self):
        self.assertIsNone(wc.parse_nbstat(b"\x00" * 20))
        self.assertIsNone(wc.parse_nbstat(b""))


class UpnpTests(unittest.TestCase):
    def test_ssdp_response(self):
        data = (b"HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=1800\r\nLOCATION: http://192.168.1.1:1900/igd.xml\r\n"
                b"SERVER: Linux/3.10 UPnP/1.0 MiniUPnPd/2.1\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n")
        h = wc.parse_ssdp_response(data)
        self.assertEqual(h["LOCATION"], "http://192.168.1.1:1900/igd.xml")
        self.assertIn("InternetGatewayDevice", h["ST"])
        self.assertIsNone(wc.parse_ssdp_response(b"garbage"))

    def test_description(self):
        d = wc.parse_upnp_description(UPNP_XML)
        self.assertEqual(d["friendlyName"], "Archer C6 & Co")  # root device, entity decoded
        self.assertEqual(d["manufacturer"], "TP-Link")
        self.assertEqual(d["modelName"], "Archer C6")

    def test_describe_only_fetches_from_the_answering_device(self):
        fetched = []
        orig = wc.lan_http_get
        wc.lan_http_get = lambda url, **kw: (fetched.append(url), (200, {}, UPNP_XML))[1]
        try:
            info = wc.describe_upnp_devices({
                "192.168.1.1": [{"LOCATION": "http://192.168.1.1:1900/igd.xml",
                                 "ST": "urn:schemas-upnp-org:device:InternetGatewayDevice:1"}],
                "192.168.1.50": [{"LOCATION": "http://evil.example.com/x.xml", "ST": "upnp:rootdevice"}],
            })
        finally:
            wc.lan_http_get = orig
        self.assertEqual(fetched, ["http://192.168.1.1:1900/igd.xml"])
        self.assertTrue(info["192.168.1.1"]["is_gateway_device"])
        self.assertEqual(info["192.168.1.1"]["modelName"], "Archer C6")
        self.assertFalse(info["192.168.1.50"]["is_gateway_device"])


# --------------------------------------------------------------------------
# Device scan, remembering devices, naming
# --------------------------------------------------------------------------

class DeviceScanTests(unittest.TestCase):
    def setUp(self):
        self.saved = {name: getattr(wc, name) for name in
                      ("udp_poke", "ping_sweep", "read_neighbor_table", "resolve_names",
                       "ssdp_discover", "describe_upnp_devices")}
        wc.udp_poke = lambda hosts: None
        wc.ping_sweep = lambda hosts: {"192.168.1.1", "192.168.1.60"}
        wc.read_neighbor_table = lambda: [("192.168.1.1", "a0:b1:c2:d3:e4:f5"),
                                          ("192.168.1.40", "da:a1:19:00:11:22"),
                                          ("192.168.1.255", "a0:b1:c2:d3:e4:f9"),
                                          ("10.0.0.5", "00:11:22:33:44:55")]
        wc.resolve_names = lambda ips: {"192.168.1.40": {"mdns": "Kitchen-iPad.local"}}
        wc.ssdp_discover = lambda ip: {"192.168.1.1": []}
        wc.describe_upnp_devices = lambda s: {"192.168.1.1": {"manufacturer": "TP-Link", "modelName": "Archer C6",
                                                              "is_gateway_device": True}}
        self.sleep = time.sleep
        wc.time.sleep = lambda s: None

    def tearDown(self):
        for name, fn in self.saved.items():
            setattr(wc, name, fn)
        wc.time.sleep = self.sleep

    def basics(self):
        return {"local_ip": "192.168.1.23", "network": "192.168.1.0/24", "gateway": "192.168.1.1"}

    def test_scan(self):
        res = wc.scan_devices(self.basics(), {"connected": True, "mac": "4c:79:6e:12:34:56"})
        ips = [d["ip"] for d in res["devices"]]
        self.assertEqual(ips, ["192.168.1.1", "192.168.1.23", "192.168.1.40", "192.168.1.60"])
        by_ip = {d["ip"]: d for d in res["devices"]}
        self.assertTrue(by_ip["192.168.1.1"]["is_router"])
        self.assertTrue(by_ip["192.168.1.23"]["is_this_computer"])
        self.assertTrue(by_ip["192.168.1.40"]["random_mac"])
        self.assertIsNone(by_ip["192.168.1.60"]["mac"])  # answered ping, not in the table
        self.assertEqual(wc.display_name(by_ip["192.168.1.40"]), "Kitchen-iPad")
        self.assertEqual(wc.display_name(by_ip["192.168.1.1"]), "TP-Link Archer C6")
        self.assertEqual(res["scanned"], 253)

    def test_public_address_is_not_scanned(self):
        basics = {"local_ip": "100.70.1.2", "network": "100.70.1.0/24", "gateway": "100.70.1.1"}
        self.assertIn("skipped", wc.scan_devices(basics, {}))

    def test_large_network_scans_local_slash24(self):
        hosts, note = wc.scan_hosts("10.0.0.0/16", "10.0.5.20")
        self.assertEqual(len(hosts), 253)
        self.assertTrue(all(h.startswith("10.0.5.") for h in hosts))
        self.assertIsNotNone(note)

    def test_known_devices_lifecycle(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "known_devices.json"
            devs1 = [{"ip": "192.168.1.1", "mac": "a0:b1:c2:d3:e4:f5", "is_router": True},
                     {"ip": "192.168.1.40", "mac": "da:a1:19:00:11:22"},
                     {"ip": "192.168.1.23", "mac": "4c:79:6e:12:34:56", "is_this_computer": True}]
            first, _ = wc.update_known_devices(path, "a0:b1:c2:d3:e4:f5", devs1, {}, "t1")
            self.assertTrue(first)
            self.assertEqual([d["status"] for d in devs1], ["router", "first scan", "you"])

            devs2 = [{"ip": "192.168.1.40", "mac": "da:a1:19:00:11:22"},
                     {"ip": "192.168.1.77", "mac": "00:11:22:33:44:55"},
                     {"ip": "192.168.1.78", "mac": "00:11:22:33:44:66"}]
            labels = {"da:a1:19:00:11:22": "My phone", "00:11:22:33:44:66": "New TV"}
            first, db = wc.update_known_devices(path, "a0:b1:c2:d3:e4:f5", devs2, labels, "t2")
            self.assertFalse(first)
            self.assertEqual([d["status"] for d in devs2], ["known", "NEW", "known"])
            self.assertEqual(devs2[0]["label"], "My phone")
            saved = json.loads(path.read_text(encoding="utf-8"))
            rec = saved["networks"]["a0:b1:c2:d3:e4:f5"]["devices"]["00:11:22:33:44:55"]
            self.assertEqual((rec["first_seen"], rec["last_seen"], rec["last_ip"]), ("t2", "t2", "192.168.1.77"))

            # a different router is a different home network, with its own list
            devs3 = [{"ip": "10.0.0.9", "mac": "00:11:22:33:44:55"}]
            first, _ = wc.update_known_devices(path, "ff:ee:dd:cc:bb:aa", devs3, {}, "t3")
            self.assertTrue(first)

    def test_corrupt_known_devices_file_is_replaced(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "known_devices.json"
            path.write_text("{not json", encoding="utf-8")
            first, _ = wc.update_known_devices(path, "k", [{"ip": "1.2.3.4", "mac": "00:11:22:33:44:55"}], {}, "t")
            self.assertTrue(first)
            self.assertIn("networks", json.loads(path.read_text(encoding="utf-8")))

    def test_name_argument_validation(self):
        args = wc.parse_args(["--name", "AA-BB-CC-DD-EE-FF", "TV"])
        self.assertEqual(args.labels, {"aa:bb:cc:dd:ee:ff": "TV"})
        with self.assertRaises(SystemExit):
            wc.parse_args(["--name", "not-a-mac", "TV"])


# --------------------------------------------------------------------------
# Speed test against a local, speed-limited server
# --------------------------------------------------------------------------

STREAM_RATE = 2_500_000  # bytes per second per connection (20 Mbps)
RESPONSE_DELAY = 0.0     # extra seconds before answering each upload


class _SpeedHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def _throttled(self, total, action):
        sent, t0, chunk = 0, time.perf_counter(), 32768
        while sent < total:
            n = min(chunk, total - sent)
            action(n)
            sent += n
            ahead = sent / STREAM_RATE - (time.perf_counter() - t0)
            if ahead > 0:
                time.sleep(ahead)

    def do_GET(self):
        if self.path.startswith("/cdn-cgi/trace"):
            body = b"fl=1\ncolo=TST\n"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        total = int(self.path.split("bytes=")[1]) if "bytes=" in self.path else 0
        self.send_response(200)
        self.send_header("Content-Length", str(total))
        self.end_headers()
        block = b"\0" * 32768
        try:
            self._throttled(total, lambda n: self.wfile.write(block[:n]))
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_POST(self):
        total = int(self.headers.get("Content-Length", 0))
        try:
            self._throttled(total, lambda n: self.rfile.read(n))
        except (ConnectionResetError, OSError):
            return
        time.sleep(RESPONSE_DELAY)  # stands in for a long round trip (e.g. satellite)
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()


class _ThreadingServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True


class SpeedTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = _ThreadingServer(("127.0.0.1", 0), _SpeedHandler)
        cls.base = "http://127.0.0.1:%d" % cls.server.server_address[1]
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def test_rate_from_samples(self):
        samples = [(0.0, 0), (1.0, 5_000_000), (2.0, 7_500_000), (4.0, 12_500_000)]
        self.assertEqual(wc.rate_from_samples(samples, 1.0), 20.0)  # warm-up excluded
        self.assertIsNone(wc.rate_from_samples([(0.0, 0)], 0))
        self.assertIsNone(wc.rate_from_samples([(0.0, 0), (1.0, 0)], 0))

    def test_full_speed_test_matches_server_limit(self):
        orig_ping = wc.ping_stats
        wc.ping_stats = lambda host, count, timeout_ms=1000: {"sent": count, "received": count,
                                                             "loss_pct": 0.0, "median_ms": 42.0}
        try:
            t0 = time.perf_counter()
            res = wc.run_speed_test(self.base, 4)
            elapsed = time.perf_counter() - t0
        finally:
            wc.ping_stats = orig_ping
        self.assertNotIn("error", res)
        self.assertEqual(res["server"], "TST")
        expected_down = 4 * STREAM_RATE * 8 / 1e6   # 4 download connections
        expected_up = 3 * STREAM_RATE * 8 / 1e6     # 3 upload connections
        self.assertAlmostEqual(res["download_mbps"], expected_down, delta=expected_down * 0.25)
        self.assertAlmostEqual(res["upload_mbps"], expected_up, delta=expected_up * 0.35)
        self.assertEqual(res["loaded_latency"]["median_ms"], 42.0)
        self.assertLess(elapsed, 20, "transfers must stop at the deadline")
        self.assertEqual(res["errors"], [])

    def test_upload_on_a_high_latency_link(self):
        """Each upload waits an extra 0.4 s for its reply; the measured rate must not drop with it."""
        global RESPONSE_DELAY
        RESPONSE_DELAY = 0.4
        try:
            res = wc.measure_upload(self.base, 6, 3)
        finally:
            RESPONSE_DELAY = 0.0
        expected = 3 * STREAM_RATE * 8 / 1e6
        self.assertAlmostEqual(res["mbps"], expected, delta=expected * 0.3)

    def test_upload_rate_ignores_quick_pieces(self):
        streams = [[(0.1, 250_000), (1.0, 2_500_000), (2.0, 5_000_000)], [(1.5, 3_750_000)]]
        self.assertEqual(wc.upload_rate(streams), 40.0)
        self.assertIsNone(wc.upload_rate([[], []]))

    def test_unreachable_server(self):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        res = wc.run_speed_test("http://127.0.0.1:%d" % port, 2)
        self.assertIn("error", res)


# --------------------------------------------------------------------------
# Advice and the report
# --------------------------------------------------------------------------

def sample_data(**over):
    d = {
        "started": "2026-11-21T10:00:00", "os": "Windows 11",
        "network": {"gateway": "192.168.1.1", "local_ip": "192.168.1.23", "network": "192.168.1.0/24",
                    "notes": []},
        "wifi": wc.finalize_wifi({"ssid": "HomeNet", "band": "2.4 GHz", "channel": 4, "rssi": -78,
                                  "rx_rate": 26, "tx_rate": 24, "standard": "802.11n",
                                  "security": "WPA-Personal", "cipher": "TKIP", "connected": True,
                                  "interface": "Wi-Fi"}),
        "nearby": [], "channels": {"scores_24": {1: 0, 6: 3, 11: 0}, "counts_24": {1: 0, 6: 2, 11: 0},
                                   "best_24": 1, "own_score": 3, "overlapping": 2},
        "latency": {"router": {"sent": 20, "received": 18, "loss_pct": 10.0, "median_ms": 45.0,
                               "jitter_ms": 25.0, "host": "192.168.1.1", "method": "ping"},
                    "Cloudflare": {"sent": 20, "received": 18, "loss_pct": 10.0, "median_ms": 60.0,
                                   "jitter_ms": 25.0, "host": "1.1.1.1", "method": "ping"}},
        "dns": [{"ip": "192.168.1.1", "label": "Your current DNS (your router)", "role": "current",
                 "median_ms": 120.0, "answered": 8, "failed": 0},
                {"ip": "1.1.1.1", "label": "Cloudflare", "role": "public", "median_ms": 15.0,
                 "answered": 8, "failed": 0}],
        "speed": {"server": "BOM", "download_mbps": 11.0, "upload_mbps": 2.0, "download_mb": 14,
                  "upload_mb": 3, "loaded_latency": {"sent": 6, "received": 6, "loss_pct": 0.0, "median_ms": 400.0}},
        "scan": {"devices": [
            {"ip": "192.168.1.1", "mac": "a0:b1:c2:d3:e4:f5", "is_router": True, "status": "router",
             "names": {}, "upnp": {"modelName": "Archer C6"}},
            {"ip": "192.168.1.23", "mac": "4c:79:6e:12:34:56", "is_this_computer": True, "status": "you",
             "names": {}},
            {"ip": "192.168.1.66", "mac": "00:11:22:33:44:55", "status": "NEW", "names": {"netbios": "UNKNOWN-PC"}},
            {"ip": "192.168.1.40", "mac": "da:a1:19:00:11:22", "random_mac": True, "status": "known",
             "names": {}, "label": "Mum's phone"},
        ]},
        "router": {"ip": "192.168.1.1", "admin_url": "http://192.168.1.1", "upnp": True,
                   "open_ports": [{"port": 23, "service": "Telnet"}, {"port": 80, "service": "web admin page"}],
                   "web": {"title": "TP-LINK"}, "model": "TP-Link Archer C6"},
        "first_device_scan": False,
    }
    d["latency"]["internet"] = dict(d["latency"]["Cloudflare"], label="Cloudflare")
    d.update(over)
    return d


class AdviceTests(unittest.TestCase):
    def titles(self, findings, level=None):
        return [f["title"] for f in findings if level is None or f["level"] == level]

    def test_bad_home_network(self):
        f = wc.build_findings(sample_data(), plan_down=100, plan_up=50)
        actions = " | ".join(self.titles(f, "ACTION"))
        for expected in ("signal is weak", "outdated security", "packets were lost",
                         "lags while the connection is busy", "only 11% of your 100 Mbps plan"):
            self.assertIn(expected, actions)
        checks = " | ".join(self.titles(f, "CHECK"))
        for expected in ("overlaps its neighbours", "wasn't there last time", "Telnet", "slow or unsteady",
                         "only 26 Mbps"):
            self.assertIn(expected, checks)
        tips = " | ".join(self.titles(f))
        self.assertIn("faster DNS", tips)
        self.assertIn("UPnP", tips)
        self.assertIn("Channel 1 looks less crowded", tips)
        self.assertEqual([x["level"] for x in f], sorted((x["level"] for x in f), key=wc.LEVEL_ORDER.get))
        # The internet loss happens at the Wi-Fi hop too, so it is not blamed on the provider.
        self.assertNotIn("beyond your router", " | ".join(self.titles(f)))

    def test_healthy_home_network(self):
        wifi = wc.finalize_wifi({"ssid": "HomeNet", "band": "5 GHz", "channel": 44, "rssi": -52,
                                 "rx_rate": 866, "tx_rate": 780, "standard": "802.11ax",
                                 "security": "WPA3-Personal", "connected": True})
        good = {"sent": 20, "received": 20, "loss_pct": 0.0, "median_ms": 3.0, "jitter_ms": 1.0, "method": "ping"}
        inet = dict(good, median_ms=14.0, label="Cloudflare")
        d = sample_data(wifi=wifi, channels={}, latency={"router": good, "Cloudflare": inet, "internet": inet},
                        dns=[{"ip": "192.168.1.1", "label": "Your current DNS", "role": "current", "median_ms": 12.0},
                             {"ip": "1.1.1.1", "label": "Cloudflare", "role": "public", "median_ms": 10.0}],
                        speed={"download_mbps": 280.0, "upload_mbps": 95.0,
                               "loaded_latency": {"sent": 6, "received": 6, "loss_pct": 0.0, "median_ms": 20.0}},
                        scan={"devices": [{"ip": "192.168.1.1", "mac": "a0:b1:c2:d3:e4:f5", "status": "router",
                                           "is_router": True, "names": {}}]},
                        router={"ip": "192.168.1.1", "open_ports": [], "upnp": False})
        f = wc.build_findings(d, plan_down=300, plan_up=100)
        self.assertEqual(self.titles(f, "ACTION"), [])
        self.assertEqual(self.titles(f, "CHECK"), [])
        good_titles = " | ".join(self.titles(f, "GOOD"))
        for expected in ("signal is strong", "fast 5 GHz", "WPA3", "quick and steady", "93% of your 300",
                         "95% of your 100", "stays low", "DNS lookups are quick", "No new devices"):
            self.assertIn(expected, good_titles)

    def test_isp_problem_not_blamed_on_wifi(self):
        router = {"sent": 20, "received": 20, "loss_pct": 0.0, "median_ms": 2.0, "jitter_ms": 0.5}
        inet = {"sent": 20, "received": 17, "loss_pct": 15.0, "median_ms": 150.0, "jitter_ms": 40.0,
                "label": "Cloudflare"}
        wifi = wc.finalize_wifi({"ssid": "x", "band": "5 GHz", "channel": 36, "rssi": -50, "rx_rate": 600,
                                 "security": "WPA2-Personal", "connected": True})
        d = sample_data(wifi=wifi, latency={"router": router, "internet": inet}, channels={},
                        speed={"download_mbps": 20.0})
        f = wc.build_findings(d, plan_down=100)
        text = " | ".join(self.titles(f))
        self.assertIn("beyond your router", text)
        detail = next(x["detail"] for x in f if "of your 100 Mbps plan" in x["title"])
        self.assertIn("router, modem or provider", detail)

    def test_router_that_answers_pings_slowly_is_not_blamed(self):
        router = {"sent": 20, "received": 20, "loss_pct": 0.0, "median_ms": 40.0, "jitter_ms": 30.0}
        inet = {"sent": 20, "received": 20, "loss_pct": 0.0, "median_ms": 12.0, "jitter_ms": 1.0}
        d = sample_data(latency={"router": router, "internet": inet})
        self.assertNotIn("slow or unsteady", " | ".join(self.titles(wc.build_findings(d))))

    def test_open_network_and_first_scan(self):
        wifi = wc.finalize_wifi({"ssid": "x", "security": "Open", "connected": True, "rssi": -50})
        d = sample_data(wifi=wifi, first_device_scan=True,
                        scan={"devices": [{"ip": "192.168.1.5", "mac": "00:11:22:33:44:55", "status": "first scan"}]})
        f = wc.build_findings(d)
        self.assertIn("not properly protected", " | ".join(self.titles(f, "ACTION")))
        self.assertIn("saved as your starting list", " | ".join(self.titles(f, "TIP")))

    def test_windows_location_note_and_no_internet(self):
        wifi = wc.finalize_wifi({"note": wc.WIN_LOCATION_HINT})
        d = sample_data(wifi=wifi, latency={"router": {"sent": 20, "received": 0, "loss_pct": 100.0},
                                            "Cloudflare": {"sent": 20, "received": 0, "loss_pct": 100.0}},
                        speed={"error": "URLError: no route", "hint": None})
        f = wc.build_findings(d)
        text = " | ".join(self.titles(f))
        self.assertIn("hidden by the system", text)
        self.assertIn("No replies from the internet", text)
        self.assertIn("couldn't run", text)
        self.assertNotIn("isn't using Wi-Fi", text)

    def test_report_renders(self):
        d = sample_data()
        f = wc.build_findings(d, 100, 50)
        text = wc.render_report(d, f)
        for expected in ("SUMMARY", "1. YOUR WI-FI CONNECTION", "-78 dBm - Weak", "2.4 GHz, channel 4",
                         "5. DEVICES ON YOUR NETWORK RIGHT NOW (4)", "Mum's phone", "UNKNOWN-PC",
                         "Archer C6 [your router]", "private address", "ROUTER CHECKLIST",
                         "http://192.168.1.1", "Telnet (23)"):
            self.assertIn(expected, text)
        self.assertTrue(all(len(line) <= 100 for line in text.splitlines()), "keep lines readable")
        text.encode("ascii")  # plain ASCII, safe for any Windows console

    def test_report_with_nothing_measured(self):
        d = {"started": "2026-11-21T10:00:00", "os": "Linux", "network": {"notes": []}, "wifi": {},
             "nearby": [], "channels": {}, "latency": {}, "dns": []}
        text = wc.render_report(d, wc.build_findings(d))
        self.assertIn("Not connected by Wi-Fi", text)
        self.assertIn("Router not found", text)


SYSTEM_PROFILER_JSON = """{
  "SPAirPortDataType" : [
    {
      "spairport_airport_interfaces" : [
        {
          "_name" : "en0",
          "spairport_airdrop_channel" : 44,
          "spairport_current_network_information" : {
            "_name" : "HomeNet",
            "spairport_network_channel" : "149 (5GHz, 80MHz)",
            "spairport_network_country_code" : "IN",
            "spairport_network_mcs" : 5,
            "spairport_network_phymode" : "802.11ac",
            "spairport_network_rate" : 234,
            "spairport_network_type" : "spairport_network_type_station",
            "spairport_security_mode" : "spairport_security_mode_wpa2_personal",
            "spairport_signal_noise" : "-71 dBm / -90 dBm"
          },
          "spairport_status_information" : "spairport_status_connected",
          "spairport_supported_channels" : ["1 (2GHz)", "36 (5GHz)"],
          "spairport_wireless_mac_address" : "f0:2f:4b:aa:bb:cc",
          "spairport_airport_other_local_wireless_networks" : [
            {"_name" : "Neighbour", "spairport_network_channel" : 6, "spairport_network_phymode" : "802.11",
             "spairport_security_mode" : "spairport_security_mode_none",
             "spairport_signal_noise" : "-70 dBm / -92 dBm"},
            {"_name" : "Flat3", "spairport_network_channel" : "36 (5GHz, 80MHz)",
             "spairport_security_mode" : "spairport_security_mode_wpa3_transition"}
          ]
        },
        {"_name" : "awdl0", "spairport_wireless_mac_address" : "2a:bb:cc:dd:ee:ff"}
      ]
    }
  ]
}"""


class ReviewFollowUps(unittest.TestCase):
    """Cases found in an independent review, each of which used to give wrong or missing advice."""

    def titles(self, findings, level=None):
        return " | ".join(f["title"] for f in findings if level is None or f["level"] == level)

    def test_mac_json_is_used_and_language_independent(self):
        info, nearby = wc.parse_system_profiler_json("2026-11-21 warning on stderr\n" + SYSTEM_PROFILER_JSON)
        wc.finalize_wifi(info)
        self.assertEqual((info["interface"], info["ssid"], info["channel"], info["band"]), ("en0", "HomeNet", 149, "5 GHz"))
        self.assertEqual((info["rssi"], info["noise"], info["tx_rate"]), (-71, -90, 234))
        self.assertEqual(info["security"], "WPA2 Personal")
        self.assertEqual(info["security_level"], "good")
        self.assertEqual(info["hw_mac"], "f0:2f:4b:aa:bb:cc")
        levels = [wc.finalize_wifi(n)["security_level"] for n in nearby]
        self.assertEqual(levels, ["critical", "strong"])
        self.assertEqual((nearby[0]["channel"], nearby[0]["band"]), (6, "2.4 GHz"))
        self.assertIsNone(wc.parse_system_profiler_json("not json"))
        self.assertEqual(wc.parse_system_profiler_json('{"SPAirPortDataType": []}'), ({}, []))

    def test_windows_route_fallback_and_adapter_names(self):
        self.assertEqual(wc.parse_ps_routes("192.168.1.1 35\r\n10.8.0.1 101\r\n0.0.0.0 5\r\n"), ("192.168.1.1", None))
        out = "127.0.0.1/8/Loopback Pseudo-Interface 1\r\n192.168.1.23/24/Wi-Fi\r\n192.168.1.30/24/Ethernet 2\r\n"
        self.assertEqual((wc.parse_ps_prefix(out, "192.168.1.23"), wc.parse_ps_alias(out, "192.168.1.23")), (24, "Wi-Fi"))
        self.assertEqual(wc.parse_ps_alias(out, "192.168.1.30"), "Ethernet 2")
        self.assertTrue(wc.WIN_VPN_ALIAS_RE.search("NordLynx"))
        self.assertFalse(wc.WIN_VPN_ALIAS_RE.search("Wi-Fi"))
        self.assertTrue(wc.VPN_IFACE_RE.match("utun3"))
        self.assertFalse(wc.VPN_IFACE_RE.match("en0"))

    def test_networkmanager_signal_scale(self):
        nets = wc.parse_nmcli_wifi(NMCLI)
        active = next(n for n in nets if n["in_use"])
        self.assertEqual(active["rssi"], 78 - 120)            # connected: 30..100 % = -90..-20 dBm
        self.assertEqual(nets[0]["rssi"], round(-40 - 35 * 0.6))  # others: 0..100 % = -100..-40 dBm
        self.assertEqual(wc.signal_label(nets[0]["rssi"]), "Good")  # 65 % is a good signal, not "fair"

    def test_which_connection_carries_traffic(self):
        self.assertTrue(wc.wifi_carries_traffic({"interface": "wlan0"}, {"connected": True, "interface": "wlan0"}))
        self.assertTrue(wc.wifi_carries_traffic({"interface": "Wi-Fi"}, {"connected": True, "interface": "wi-fi"}))
        self.assertFalse(wc.wifi_carries_traffic({"interface": "eth0"}, {"connected": True, "interface": "wlan0"}))
        self.assertIsNone(wc.wifi_carries_traffic({"interface": None}, {"connected": True, "interface": "en0"}))
        self.assertFalse(wc.wifi_carries_traffic({"interface": "en0"}, {"connected": False}))

    def test_hidden_windows_details_get_neutral_advice(self):
        d = sample_data(wifi=wc.finalize_wifi({"note": wc.WIN_LOCATION_HINT}), speed={"download_mbps": 20.0,
                        "upload_mbps": 10.0})
        f = wc.build_findings(d, plan_down=100)
        detail = next(x["detail"] for x in f if "of your 100 Mbps plan" in x["title"])
        self.assertIn("Wi-Fi details were hidden", detail)
        self.assertNotIn("didn't go over Wi-Fi", detail)

    def test_laptop_on_cable_and_wifi(self):
        wifi = wc.finalize_wifi({"ssid": "x", "band": "5 GHz", "channel": 36, "rssi": -50, "rx_rate": 200,
                                 "security": "WPA2-Personal", "connected": True, "interface": "wlan0"})
        wifi["carries_traffic"] = False
        d = sample_data(wifi=wifi, channels={}, speed={"download_mbps": 40.0, "upload_mbps": 10.0},
                        network={"interface": "eth0", "notes": []})
        f = wc.build_findings(d, plan_down=500)
        text = self.titles(f)
        self.assertIn("also connected by cable", text)
        self.assertNotIn("can't carry your full", text)
        detail = next(x["detail"] for x in f if "of your 500 Mbps plan" in x["title"])
        self.assertIn("didn't go over Wi-Fi", detail)
        loss = next(x for x in f if "lost between this computer and the router" in x["title"])
        self.assertIn("cable", loss["detail"])

    def test_loss_when_router_ignores_pings(self):
        inet = {"sent": 20, "received": 16, "loss_pct": 20.0, "median_ms": 20.0, "jitter_ms": 2.0}
        d = sample_data(latency={"router": {"sent": 20, "received": 0, "loss_pct": 100.0}, "internet": inet})
        text = self.titles(wc.build_findings(d))
        self.assertIn("doesn't answer pings", text)
        self.assertIn("20% of packets to the internet were lost", text)
        self.assertNotIn("beyond your router", text)

    def test_loss_when_router_answers_slowly(self):
        router = {"sent": 20, "received": 14, "loss_pct": 30.0, "median_ms": 40.0, "jitter_ms": 5.0}
        inet = {"sent": 20, "received": 14, "loss_pct": 30.0, "median_ms": 12.0, "jitter_ms": 2.0}
        text = self.titles(wc.build_findings(sample_data(latency={"router": router, "internet": inet})))
        self.assertIn("30% of packets to the internet were lost", text)

    def test_bufferbloat_compares_the_same_server(self):
        cf = {"sent": 20, "received": 20, "loss_pct": 0.0, "median_ms": 45.0, "jitter_ms": 1.0}
        google = dict(cf, median_ms=8.0)
        lat = {"router": dict(cf, median_ms=2.0), "Cloudflare": cf, "Google": google,
               "internet": dict(google, label="Google")}
        speed = {"download_mbps": 100.0, "upload_mbps": 20.0,
                 "loaded_latency": {"sent": 6, "received": 6, "loss_pct": 0.0, "median_ms": 46.0}}
        f = wc.build_findings(sample_data(latency=lat, speed=speed))
        self.assertIn("stays low", self.titles(f, "GOOD"))

    def test_bufferbloat_with_timed_out_replies(self):
        speed = {"download_mbps": 50.0, "upload_mbps": 10.0,
                 "loaded_latency": {"sent": 6, "received": 0, "loss_pct": 100.0}}
        f = wc.build_findings(sample_data(speed=speed))
        self.assertIn("100% of replies lost", self.titles(f, "ACTION"))

    def test_idle_link_rate_disproved_by_download(self):
        wifi = wc.finalize_wifi({"ssid": "x", "band": "5 GHz", "channel": 36, "rssi": -50, "rx_rate": 6,
                                 "tx_rate": 6, "security": "WPA2-Personal", "connected": True})
        f = wc.build_findings(sample_data(wifi=wifi, channels={}, speed={"download_mbps": 300.0, "upload_mbps": 50.0}),
                              plan_down=300)
        self.assertNotIn("link was running at only", self.titles(f))

    def test_weak_signal_is_not_called_interference(self):
        weak = wc.finalize_wifi({"ssid": "x", "rssi": -80, "noise": -92, "connected": True})
        noisy = wc.finalize_wifi({"ssid": "x", "rssi": -60, "noise": -75, "connected": True})
        self.assertNotIn("interference", self.titles(wc.build_findings(sample_data(wifi=weak))))
        self.assertIn("interference", self.titles(wc.build_findings(sample_data(wifi=noisy))))

    def test_partly_failed_speed_test_is_explained(self):
        speed = {"download_mbps": 80.0, "upload_mbps": None, "download_errors": [],
                 "upload_errors": ["HTTPError: HTTP Error 429: Too Many Requests"]}
        f = wc.build_findings(sample_data(speed=speed))
        item = next(x for x in f if "upload part of the speed test didn't finish" in x["title"])
        self.assertIn("429", item["detail"])
        text = wc.render_report(sample_data(speed=dict(speed, download_mb=80, upload_mb=0)), f)
        self.assertIn("did not finish (HTTPError: HTTP Error 429", text)


class EndToEnd(unittest.TestCase):
    def test_main_runs_and_saves_reports(self):
        """Runs the real program here (whatever this machine's network is) without the scan or speed test."""
        orig = wc.check_router
        wc.check_router = lambda gw: {"ip": gw, "open_ports": [], "admin_url": "http://%s" % gw}
        try:
            with tempfile.TemporaryDirectory() as tmp:
                rc = wc.main(["--no-scan", "--no-speed", "--quick", "--out", tmp])
                self._check_output(rc, tmp)
        finally:
            wc.check_router = orig

    def _check_output(self, rc, tmp):
        if True:
            self.assertEqual(rc, 0)
            files = sorted(os.listdir(tmp))
            self.assertTrue(any(f.endswith(".txt") for f in files), files)
            jf = next(f for f in files if f.endswith(".json"))
            data = json.loads(Path(tmp, jf).read_text(encoding="utf-8"))
            self.assertIn("findings", data)


if __name__ == "__main__":
    unittest.main()
