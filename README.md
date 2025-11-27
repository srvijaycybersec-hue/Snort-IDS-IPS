
Snort 2.9.20 – Installation, Configuration, and Rule Testing Guide

Overview

This document provides a complete walkthrough for installing Snort 2.9.20, configuring it in IDS mode, creating custom detection rules for anonymous ping  request, SSH login attempts, and SQL Injection attempts, and validating whether alerts are triggered.

---

1. Install Dependencies

sudo apt update
sudo apt install -y build-essential autotools-dev libdumbnet-dev \
libluajit-5.1-dev libpcap-dev libpcre3-dev zlib1g-dev \
libssl-dev pkg-config libnghttp2-dev libpcre++-dev \
flex bison


---

2. Download and Install Snort 2.9.20

2.1 Install Snort directly on your VMs. I used Ubuntu vm to install snort using following command

sudo apt install snort -y

___

2.2 Verify Installation

snort -V

You may see:

Snort Version 2.9.20

---

3. Basic Snort Configuration

3.1 Edit snort.conf

sudo nano /etc/snort/snort.conf

Verify and update:

var RULE_PATH /etc/snort/rules
var SO_RULE_PATH /etc/snort/so_rules
var PREPROC_RULE_PATH /etc/snort/preproc_rules

Enable local rules:

include $RULE_PATH/local.rules

Set HOME_NET: 192.168.56.0/24 (You should give your entire network ip address like 192.168.1.0/24)

ipvar HOME_NET any

Save and exit.


---

4. Custom Rules Creation

4.1 FTP Anonymous Login Detection Rule

Detects user anonymous in FTP authentication.

alert tcp any any -> any 21 (msg:"FTP Anonymous Login Attempt"; sid:1000001; rev:1;)

Add inside:

sudo nano /etc/snort/rules/local.rules


---

4.2 SSH Login Attempt Rule

Detect inbound SSH (port 22) connection attempts:

alert tcp any any -> any 22 (msg:"SSH Login Attempt Detected"; sid:1000002; rev:1;)


---

4.3 SQL Injection Attempt Rule

Detect common SQLi payloads:

alert tcp any any -> any 80 (msg:"SQL Injection Attempt"; flow:to_server,established; content:"' OR 1=1 --"; nocase; sid:1000003; rev:1;)

For wildcard SQLi keywords:

alert tcp any any -> any 80 (msg:"SQL Injection Keyword Detected"; flow:to_server,established; pcre:"/(\bunion\b|\bselect\b|\bdrop\b|\binsert\b|\bor\b|\band\b)/i"; sid:1000004; rev:1;)

Save the file.


---

5. Testing Snort Rules

5.1 Start Snort in IDS Mode

sudo snort -A console -q -c /etc/snort/snort.conf -i ensp0s8

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
