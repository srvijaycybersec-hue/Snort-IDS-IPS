
Snort 2.9.20 – Installation, Configuration, and Rule Testing Guide

Overview

This document provides a complete walkthrough for installing Snort 2.9.20, configuring it in IDS mode, creating custom detection rules for FTP anonymous login, SSH login attempts, and SQL Injection attempts, and validating whether alerts are triggered.


---

1. System Requirements

Ubuntu 18/20/22 (recommended)

Root or sudo access

At least 2 GB RAM

Internet connection



---

2. Install Dependencies

sudo apt update
sudo apt install -y build-essential autotools-dev libdumbnet-dev \
libluajit-5.1-dev libpcap-dev libpcre3-dev zlib1g-dev \
libssl-dev pkg-config libnghttp2-dev libpcre++-dev \
flex bison


---

3. Download and Install Snort 2.9.20

3.1 Download the source

cd /usr/local/src
sudo wget https://www.snort.org/downloads/snort/snort-2.9.20.tar.gz
sudo tar -xvzf snort-2.9.20.tar.gz
cd snort-2.9.20

3.2 Configure and Install

sudo ./configure --enable-sourcefire
sudo make
sudo make install

3.3 Verify Installation

snort -V

You should see:

Snort Version 2.9.20


---

4. Snort Directory Setup

sudo mkdir -p /etc/snort/rules
sudo mkdir /var/log/snort
sudo chmod -R 777 /var/log/snort
sudo touch /etc/snort/rules/local.rules
sudo cp etc/* /etc/snort/


---

5. Basic Snort Configuration

5.1 Edit snort.conf

sudo nano /etc/snort/snort.conf

Verify and update:

var RULE_PATH /etc/snort/rules
var SO_RULE_PATH /etc/snort/so_rules
var PREPROC_RULE_PATH /etc/snort/preproc_rules

Enable local rules:

include $RULE_PATH/local.rules

Set HOME_NET:

ipvar HOME_NET any

Save and exit.


---

6. Custom Rules Creation

6.1 FTP Anonymous Login Detection Rule

Detects user anonymous in FTP authentication.

alert tcp any any -> any 21 (msg:"FTP Anonymous Login Attempt"; flow:to_server,established; content:"USER anonymous"; nocase; sid:10001; rev:1;)

Add inside:

sudo nano /etc/snort/rules/local.rules


---

6.2 SSH Login Attempt Rule

Detect inbound SSH (port 22) connection attempts:

alert tcp any any -> any 22 (msg:"SSH Login Attempt Detected"; flags:S; sid:10002; rev:1;)


---

6.3 SQL Injection Attempt Rule

Detect common SQLi payloads:

alert tcp any any -> any 80 (msg:"SQL Injection Attempt"; flow:to_server,established; content:"' OR 1=1 --"; nocase; sid:10003; rev:1;)

For wildcard SQLi keywords:

alert tcp any any -> any 80 (msg:"SQL Injection Keyword Detected"; flow:to_server,established; pcre:"/(\bunion\b|\bselect\b|\bdrop\b|\binsert\b|\bor\b|\band\b)/i"; sid:10004; rev:1;)

Save the file.


---

7. Testing Snort Rules

7.1 Start Snort in IDS Mode

sudo snort -A console -q -c /etc/snort/snort.conf -i eth0

If your interface is different:

ip a

Use the correct interface name.


---

8. Triggering Each Alert

8.1 Test FTP Anonymous Login Rule

From another machine or local system:

ftp localhost
Name: anonymous

Snort output should show:

FTP Anonymous Login Attempt


---

8.2 Test SSH Login Rule

ssh user@localhost

Snort output should show:

SSH Login Attempt Detected


---

8.3 Test SQL Injection Rule

Send a malicious HTTP request:

curl "http://localhost/?id=' OR 1=1 --"

Snort output should show:

SQL Injection Attempt

Or for generic keyword tests:

curl "http://localhost/?search=union select"


---

9. Verify Snort Logs

Snort logs alerts to:

/var/log/snort/alert

View logs:

cat /var/log/snort/alert


---

10. Troubleshooting

10.1 Common Error: "Unknown rule option"

Ensure syntax is correct in local.rules.

10.2 "Snort can't open pcap"

Check interface permissions:

sudo chmod o+r /dev/bpf*

10.3 Rule not triggering

Verify Snort is running on correct interface.

Test using same HOME_NET configuration.

Check flow keywords (remove flow if needed).



---

11. Stopping Snort

Press:

CTRL + C


---

12. Conclusion

You now have a fully functional Snort 2.9.20 setup with custom rules for:

FTP anonymous login detection

SSH login attempt detection

SQL injection detection


All alerts can be observed live in console mode or via Snort log files.
