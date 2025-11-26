# My Personal Project: Building an Automated Malware Detection System with Wazuh

-----

## 1. Summary

This lab focuses on combining log monitoring (**Wazuh**) with threat intelligence (**VirusTotal**) to detect advanced threats like **Mimikatz** and automate the containment process

-----

## 2. My Lab Setup

* **Server:** Wazuh Manager running on Debian 13 (Trixie)
* **Victim Machine:** Windows 11 with Wazuh Agent installed
* **Tools:** VirusTotal (Free API), [Mimikatz](github.com/gentilkiwi/mimikatz) (for simulation)

-----

## 3\. The Flow

1. **Attack Simulation:** Drop a malicious file into the Windows `Downloads` folder
2. **Detection:** Wazuh detects the new file and cross-references the file hash with VirusTotal
3. **Alerting:** If VirusTotal flags the file as malicious, Wazuh generates a high-severity alert
4. **Response:** Wazuh immediately triggers a script to shutdown the system, effectively quarantining the endpoint and preventing further malware execution

-----

## 4. Implementation

### Step 1: Connecting VirusTotal

First, I obtained a free API Key from VirusTotal. Then, I configured the Wazuh Manager to enable the integration

**Configuration (`/var/ossec/etc/ossec.conf` on Manager):**

```xml
<integration>
  <name>virustotal</name>
  <api_key>API_KEY_HERE</api_key> 
  <group>syscheck</group>
  <alert_format>json</alert_format>
</integration>
```

![alt text](<image-1.png>)

(I replaced `API_KEY_HERE` with my actual API key)

### Step 2: Observing the `Downloads` folder

On the Windows machine, I set up File Integrity Monitoring (FIM). I focused on the `Downloads` folder as it is a common entry point for malware

**Configuration (`ossec-agent\ossec.conf` on Agent):**

```xml
<syscheck>
  <directories check_all="yes" realtime="yes">C:\Users\USER_NAME\Downloads</directories>
</syscheck>
```

![alt text](<image.png>)

(I replaced `USER_NAME` with my actual Windows username)

### Step 3: Creating Alert Rule

I wrote a custom rule to map this detection to the MITRE ATT\&CK framework (T1003 - OS Credential Dumping).

**My Custom Rule (`/var/ossec/etc/rules/local_rules.xml`):**

```xml
<group name="virustotal,">
  <rule id="100005" level="12">
    <if_sid>87105</if_sid> 
    <field name="virustotal.positives">^0</field> 
    <match negate="yes">^0</match>
    <description>Wazuh: Malware detected! Positive match: $(virustotal.positives)</description>
    <mitre>
      <id>T1003</id>
    </mitre>
  </rule>
</group>
```

![alt text](<image-3.png>)

### Step 4: Active Response

This was the most challenging part of the lab. My goal was to automate the response action to neutralize the threat immediately

**1. Challenges & Strategic Pivot**
Initially, I attempted to write a script to delete the specific malware file. However, I encountered significant technical hurdles:

* **Input Parsing Issues:** The Windows Agent struggled to parse the JSON parameters sent from the Manager, often resulting in "Empty Input" errors.
* **Permission Issues:** The `SYSTEM` account on Windows had restrictions accessing the temporary files needed for data passing.

Rather than getting stuck on a specific technical constraint, I decided to pivot the strategy from "File Deletion" to "System Quarantine". I configured the system to Force Shutdown the infected machine. This approach is robust, input-independent, and effectively stops the attack chain

**2. Manager Configuration:**
I configured the Manager in `/var/ossec/etc/ossec.conf` to run a command called `win-emergency-logoff` when Rule 87105 (VirusTotal detection) is triggered.

```xml
<command>
  <name>win-emergency-logoff</name>
  <executable>emergency-logoff.cmd</executable>
</command>

<active-response>
  <command>win-emergency-logoff</command>
  <location>local</location>
  <rules_id>87105</rules_id>
</active-response>
```

**3. Agent Script:**
I created a simple batch script located at `\ossec-agent\active-response\bin\` on the Victim machine to force a system shutdown upon detection:

```batch
@echo off
echo %DATE% %TIME% - MALWARE DETECTED! QUARANTINE >> "C:\Program Files (x86)\ossec-agent\active-response\active-responses.log"

shutdown /s /f /t 3 /c "ALERT: MALWARE DETECTED! SYSTEM SHUTDOWN IN 3 SECONDS"
```

![alt text](<image-4.png>)

-----

## 5\. Testing & Results

To test my lab, I downloaded a Mimikatz sample into the Downloads folder.

**The Result:**

1. Within seconds, I saw the alert on my Dashboard
2. The Warning Box appeared on the Windows screen
3. The system successfully shut down to isolate the threat

![alt text](<image-5.png>)

![alt text](<image-2.png>)
