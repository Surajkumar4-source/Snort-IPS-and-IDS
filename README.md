# Snort-IPS-and-IDS

*In this Guide we cover installation and configuration of Snort in Inline Mode on CentOS VM systems, along with rule creation for detecting various types of network traffic*



### Intrusion Prevention System (IPS)
  *An Intrusion Prevention System (IPS) is a network security technology designed to monitor network traffic, detect potential threats or malicious activity, and prevent those threats from reaching their targets. IPSs are proactive devices that analyze network traffic for suspicious patterns, logging relevant information, attempting to block attacks, and reporting these activities for further analysis.*

### Core Functions of IPS:
- Identification of Suspicious Activity: Monitors traffic for potential signs of attacks.
- Logging: Keeps a record of suspicious activity for analysis.
- Blocking: Attempts to block malicious traffic from continuing or spreading.
- Reporting: Provides logs and alerts to administrators regarding potential threats.


### Detection Mechanisms Used by IPS:

- Address Matching: Detects suspicious patterns based on IP addresses.
- HTTP String and Substring Matching: Looks for harmful patterns in HTTP traffic.
- Pattern Matching: Detects known attack signatures.
- TCP Connection Analysis: Examines the integrity and status of connections.
- Packet Anomaly Detection: Identifies abnormal packets.
- Traffic Anomaly Detection: Identifies abnormal traffic patterns.
- Port Matching: Monitors TCP/UDP ports for irregularities.

## IPS Classifications:
1. Network-Based IPS (NIPS): Monitors and analyzes network traffic to detect malicious activity across the entire network.

2. Wireless IPS (WIPS): Specifically monitors wireless networks for unusual or malicious activity.

3. Host-Based IPS (HIPS): Monitors a single host for malicious activity, such as file system changes or system calls.

## IPS Detection Methods:
- Signature-Based Detection: Compares network traffic against known attack signatures.
- Anomaly-Based Detection: Compares network traffic with baseline "normal" patterns to detect deviations.


<br>

<br>



# Intrusion Detection System (IDS)

An Intrusion Detection System (IDS) is a security tool that monitors network or system activity for malicious actions or policy violations. Unlike IPS, IDS is a passive system that detects and alerts but does not actively block threats.

## Core Functions of IDS
1. **Monitoring**: Continuously inspects network traffic or system activities.
2. **Detection**: Identifies suspicious or malicious behavior.
3. **Alerting**: Notifies administrators about potential threats.
4. **Logging**: Records data for further analysis.

---

## IDS Types
1. **Network-Based IDS (NIDS)**:
   - Monitors entire network traffic for malicious patterns.
2. **Host-Based IDS (HIDS)**:
   - Focuses on monitoring activities on a specific host or system.

---

## IDS Detection Methods
1. **Signature-Based Detection**:
   - Matches traffic patterns to a database of known attack signatures.
2. **Anomaly-Based Detection**:
   - Identifies deviations from normal behavior to detect unknown threats.

---

## Key Difference from IPS
- **IDS**: Detects and alerts but does not block threats.
- **IPS**: Actively prevents and blocks malicious activity.








<br>

<br>














# ------------Implementation Setup---------------


<br>

<br>



## Step 1. Snort Installation on CentOS 7

1. Install Dependencies:
```yml

yum install -y zlib-devel libpcap-devel pcre-devel libdnet-devel openssl-devel libnghttp2-devel luajit-devel gcc flex flex-devel bison

```

  - Installs essential development libraries and tools required for Snort's installation and compilation.


2. Download and Install DAQ:
   
```yml
wget https://www.snort.org/downloads/snort/daq-2.0.7.tar.gz

tar -xzvf daq-2.0.7.tar.gz

cd daq-2.0.7

./configure && make && make install

```

  - Downloads, extracts, and installs the Data Acquisition (DAQ) library required by Snort.


3. Download and Install Snort:
```yml

wget https://www.snort.org/downloads/snort/snort-2.9.20.tar.gz

tar -xzvf snort-2.9.20.tar.gz

cd snort-2.9.20

./configure --enable-sourcefire --disable-open-appid

make

make install

```

  - Downloads, extracts, and installs Snort. The --enable-sourcefire flag configures Snort to use the Sourcefire-specific features.
    
3. Update Library and Create Symlink:

```yml
ldconfig

ln -s /usr/local/bin/snort /usr/sbin/snort

```

  - ldconfig updates the system's dynamic linker run-time bindings. The ln -s command creates a symbolic link for easy access to the Snort binary.
    
4. Create Necessary Directories and Set Permissions:

```yml

sudo groupadd snort

sudo useradd snort -r -s /sbin/nologin -c SNORT_IDS -g snort

sudo mkdir -p /etc/snort/rules

sudo mkdir /var/log/snort

sudo mkdir /usr/local/lib/snort_dynamicrules

sudo chmod -R 5775 /etc/snort /var/log/snort /usr/local/lib/snort_dynamicrules

sudo chown -R snort:snort /etc/snort /var/log/snort /usr/local/lib/snort_dynamicrules

```

  - Creates a snort user and group, along with necessary directories for Snort's configuration, logs, and rules. The chmod and chown commands set appropriate permissions and ownership for these directories.

5. Download and Copy Snort Configuration Files:
```yml

sudo cp -av ~/snort-2.9.20/etc/*.conf* /etc/snort

sudo cp -av ~/snort-2.9.20/etc/*.map /etc/snort

```
  - Copies Snort configuration files from the installation directory to the /etc/snort directory.

6. Download and Set Up Snort Rules:

```yml
wget https://www.snort.org/rules/community -O ~/community.tar.gz

tar -xvf ~/community.tar.gz -C ~/

cp ~/community-rules/* /etc/snort/rules

```

7. Downloads and extracts Snort's community rules, then copies them to the Snort rules directory.
  - Modify Snort Configuration File:

```yml
var RULE_PATH /etc/snort/rules

var SO_RULE_PATH /etc/snort/so_rules

var PREPROC_RULE_PATH /etc/snort/preproc_rules

var WHITE_LIST_PATH /etc/snort/rules

var BLACK_LIST_PATH /etc/snort/rules

```

  - Sets rule paths within the Snort configuration file (snort.conf).



8. Update DAQ Configuration
  - Edit /etc/snort/snort.conf and add:

```yml
config daq: afpacket
config daq_mode: inline
config daq_var: buffer_size_mb=512
```
  - Explanation: Configures Snort to use the inline mode with optimized buffer size.




9. Test Configuration:

```yml

snort -T -i eth0 -c /etc/snort/snort.conf

```
  - Tests the Snort configuration file (snort.conf) for errors and verifies the network interface (eth0).
    
10. Run Snort as a Daemon:

```
snort -D
```
  - Runs Snort in the background (as a daemon), allowing continuous monitoring.

11. Monitoring and Logs
  - To monitor traffic and alerts:

```yml
snort -A console -q -i eth0 -c /etc/snort/snort.conf
```






<br>
<br.






## Step 2 Snort Rule Creation:
  - Rule Structure:
      - Rule Header: Contains the action, protocol, source and destination IP addresses, source and destination ports.
      - Rule Options: Contains alert messages and defines the part of the packet to inspect for rule triggering.

*Rule Syntax Example:*

```yml

<action> <protocol> <source_ip> <source_port> -> <destination_ip> <destination_port> (msg:"<message>"; sid:"<signature>"; rev:1;)

  ```

*Rule Types:*

- alert: Generate an alert and log the packet.
- log: Log the packet.
- pass: Ignore the packet.
- drop: Block the packet and log it.
- reject: Block the packet, log it, and send a TCP reset.
- sdrop: Block the packet and do not log it.




# Snort Rule Examples 

  *This provides examples of Snort rules and a brief explanation of each command for quick reference.*



1. Detect Any IP Packet
```yml
alert ip any any -> any any (msg: "IP Packet detected"; sid: 10000; rev:1;)
```

  - Description: Detects all IP packets, regardless of source or destination.

      - Components:
- alert: Specifies the action to take (alert in this case).
- ip: Monitors all IP traffic.
- any any: Matches any source and destination IP and port.
-msg: Custom message displayed when a rule is triggered.
- sid: Unique identifier for the rule.
- rev: Revision number of the rule.


2. Detect PING (ICMP) Packets
```yml
alert icmp any any -> $HOME_NET any (msg: "Ping from suraj"; sid: 1000001; rev: 1;)
```
 - Description: Detects ICMP packets (commonly used for ping) destined for the $HOME_NET.
      - Components:
- icmp: Protocol type for Internet Control Message Protocol (ICMP).
- $HOME_NET: Placeholder for the protected network.
- msg, sid, rev: Same as above.

3. Detect FTP Connections
```yml
alert tcp any any -> $HOME_NET 21 (msg: "FTP Connection"; sid: 1000002; rev: 1;)
```
  - Description: Detects TCP packets targeting port 21, commonly used for FTP connections.
    - Components:
- tcp: Protocol type for Transmission Control Protocol (TCP).
- 21: Port number for FTP.

4. Detect SYN Packets (Flag Detection)

```yml
alert tcp any any -> $HOME_NET any (flags: S; msg: "SYN Packet"; sid: 1000003; rev: 1;)
```

  - Description: Detects TCP packets with the SYN flag set, typically used in connection initiation.
    - Components:
- flags: S: Matches packets with the SYN flag set.

5. Detect SSH Attempts Using Content Matching

```yml
alert tcp any any -> $HOME_NET 22 (msg: "SSH Attempt"; content: "SSH"; sid: 1000003; rev: 1;)
```
  - Description: Detects TCP packets containing the string "SSH" targeting port 22 (used for SSH connections).
    - Components:
- content: "SSH": Matches packets containing the specified string.
- 22: Port number for SSH.

6. Log SSH Attempts in ASCII Format

```yml
alert tcp any any -> $HOME_NET 22 (content: "SSH"; msg: "SSH Attempt"; sid: 1000003; rev: 1;)

snort -A console -q -i eth0 -c /etc/snort/snort.conf -K ascii

```
  - Description: Logs SSH packets in human-readable ASCII format.
      - Command Explanation:
- snort: Runs Snort for packet detection.
- -A console: Outputs alerts to the console.
- -q: Runs Snort in quiet mode (minimal output).
- -i eth0: Specifies the network interface (e.g., eth0).
- -c /etc/snort/snort.conf: Specifies the configuration file to use.
- -K ascii: Logs packets in ASCII format.







<br>

<br>



# Bypass IDS:


<br>

#### *Assignment:  The goal is to bypass the Intrusion Detection System (IDS) by encoding the payload to evade detection. The key steps include modifying the attack payload so it isn't caught by the detection rule.*




<br>


# Bypassing IDS Using Snort

*This solution demonstrates how to bypass an Intrusion Detection System (IDS) by encoding attack payloads to evade detection rules. *


### Prerequisites
1. **Snort IDS**: Installed and configured on your system.
2. **Nginx Web Server**: Running a vulnerable web application to simulate attacks.
3. **Local Rules File**: Located at `/etc/snort/rules/local.rules`.
4. **Attack Simulation Tools**: A browser or tools like `curl` for making HTTP requests.


#### Following are different ways:

### 1. Detection Rule for Local File Inclusion (LFI)

  - Rule Configuration:
    
```yml

# vim /etc/snort/rules/local.rules

var HTTP_WEB_SERVERS [x.x.x.x, x.x.x.x]

var HTTP_PORTS [80, 443]

alert $EXTERNAL_NET any -> $HTTP_WEB_SERVERS $HTTP_PORTS (msg:"LFI Attack detected"; content:"../"; sid:1000001; rev:1)

```

  - Rule Explanation:
    - Purpose: Detects LFI attacks that use ../ for directory traversal.
          - Key Components:
- $HTTP_WEB_SERVERS: IP addresses of monitored web servers.
- $HTTP_PORTS: Ports 80 (HTTP) and 443 (HTTPS).
- content:"../": Triggers when the ../ pattern (used for directory traversal) is detected in the payload.




2. LFI Attack Simulation
  - Example URL:
```yml
http://domain.tld/index.php?file=../../../etc/passwd
```
  - Description: Attempts to access the file /etc/passwd by using ../ to traverse directories.

3. Bypassing the IDS Rule
  - URL Encoding:
      - Encode the payload to avoid detection by the content:"../" rule.

```yml

# URL Encoding

. => %2E

/ => %2F

http://domain.tld/index.php?file=%2E%2E%2F%2E%2E%2F%2E%2E%2Fetc%2Fpasswd

```

  - Bypass Explanation:
- Encoded Characters:
- . becomes %2E.
- / becomes %2F.
  - Result: The encoded payload (%2E%2E%2F) bypasses the IDS rule by avoiding a direct match with ../.
 

4. Testing the Setup
  - Start Snort:
```yml
snort -A console -q -i eth0 -c /etc/snort/snort.conf
```
  - Send a Request: Use a browser or curl to access the encoded URL.
  - Check Alerts: Review Snort logs to verify detection or bypass success.

## Notes
- Ensure that Nginx and Snort are properly configured and running before testing.
- Use this guide for educational purposes only in a controlled environment.




<br>
<br>



## Assignment-2 : Prevent the Above ByPass IDS

<br>
<br>



*To prevent the bypass mentioned above using Snort in Inline Mode (IPS), you need to configure Snort with more stringent rules and settings to detect the encoded attack strings (URL Encoding) , preventing the Local File Inclusion (LFI) attack.*

### Steps to Prevent the Bypass:

1. *Modify Detection Rule to Handle Encoded Payloads: Modify the Snort rule to handle URL encoding and prevent bypassing of the LFI attack. Instead of just detecting ../, we will look for the encoded version of ../, such as %2E%2E%2F.*

### Rule to Detect Encoded Directory Traversal (%2E%2E%2F):

  - Open the Snort rule file:  `vim /etc/snort/rules/local.rules`

  - Add or modify the rule to also detect the encoded attack pattern:

```yml
alert $EXTERNAL_NET any -> $HTTP_WEB_SERVERS $HTTP_PORTS (msg:"LFI Attack detected - encoded"; content:"%2E%2E%2F"; sid:1000002; rev:1;)
```
  Explanation:

  - content:"%2E%2E%2F" matches the URL-encoded version of ../ (%2E is . and %2F is /).
  - This rule will now detect encoded LFI attacks.

2. *Add Rule to Block Malicious Traffic (Inline Mode): Once Snort is configured in Inline Mode (IPS), it can actively drop malicious packets. To ensure the bypass is blocked, add a rule to drop packets matching this attack vector.*

  - Drop Rule for Encoded Attack:

  - Add a drop rule that actively blocks traffic with encoded directory traversal patterns:

```yml
drop $EXTERNAL_NET any -> $HTTP_WEB_SERVERS $HTTP_PORTS (msg:"LFI Attack detected - drop encoded"; content:"%2E%2E%2F"; sid:1000003; rev:1;)
```
  - Explanation:

  - This rule uses drop to prevent any traffic matching the encoded directory traversal pattern (%2E%2E%2F).
  - The rule will prevent the LFI attack even if the attacker encodes the payload to bypass detection.

3. Test Snort Configuration: After adding these rules, it's essential to test Snort’s configuration to ensure that Snort can effectively detect and block encoded LFI attacks.



Start Snort in Inline Mode (IPS) to actively block malicious traffic:

```yml
    snort -A console -q -Q -i eth0:eth1 -c /etc/snort/snort.conf
```
Explanation:

  - This command runs Snort in Inline Mode (-Q), ensuring it actively blocks any malicious traffic based on the configured rules.
- -A console displays alerts in the console.



<br>

### Example of a Prevention Flow:
Let’s assume the attacker tries to bypass the IDS by using the encoded LFI attack:

```yml
http://domain.tld/index.php?file=%2E%2E%2F%2E%2E%2F%2E%2E%2Fetc%2Fpasswd
```
  - With the above Snort rules in Inline Mode:

  - The Snort detection rule will identify %2E%2E%2F (the encoded version of ../).
  - The drop rule will block the request from reaching the server, preventing the attack.






















<br>
<br>
<br>
<br>



**👨‍💻 𝓒𝓻𝓪𝓯𝓽𝓮𝓭 𝓫𝔂**: [Suraj Kumar Choudhary](https://github.com/Surajkumar4-source) | 📩 **𝓕𝓮𝓮𝓵 𝓯𝓻𝓮𝓮 𝓽𝓸 𝓓𝓜 𝓯𝓸𝓻 𝓪𝓷𝔂 𝓱𝓮𝓵𝓹**: [csuraj982@gmail.com](mailto:csuraj982@gmail.com)





<br>



