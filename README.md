# WifiDeauth

## Description
This package implement a Dos attack on Wifi (protocol: 802.11) named Deauth.

## Requirements
This package require :
 - python3
 - python3 Standard Library
 - Scapy

## Installation
```bash
pip install WifiDeauth
```

## Examples

### Command lines
```bash
WifiDeauth -h
WifiDeauth --help
WifiDeauth -vvvvv # max verbose level
WifiDeauth -i "wlan0" # use specific interface
WifiDeauth -t "0A*" # using glob syntax to define targets
WifiDeauth -b "^([a-fA-F0-9]{2}:?){6}$" # using regex syntax to define BSSID
```

### Python3
```python
from WifiDeauth import WifiDeauth
deauth = WifiDeauth(targets="0A*", bssid="^([a-fA-F0-9]{2}:?){6}$", interface="wlan0", debug=5)
deauth.sniff()
```

### Python executable:
```bash
python3 -m pip install scapy # install requirements
python3 WifiDeauth.pyz -vvvvv

# OR
python3 -m pip install scapy # install requirements
chmod u+x WifiDeauth.pyz # add execute rights
./WifiDeauth.pyz -b "*" # execute file
```

### Python module (command line):

```bash
python3 -m WifiDeauth
python3 -m WifiDeauth.WifiDeauth -i "wlan0"
```

## Links
 - [Github Page](https://github.com/mauricelambert/WifiDeauth)
 - [Documentation WifiDeauth](https://mauricelambert.github.io/info/python/security/WifiDeauth/WifiDeauth.html)
 - [Download as python executable](https://mauricelambert.github.io/info/python/security/WifiDeauth.pyz)
 - [Pypi package](https://pypi.org/project/WifiDeauth/)

## Licence
Licensed under the [GPL, version 3](https://www.gnu.org/licenses/).