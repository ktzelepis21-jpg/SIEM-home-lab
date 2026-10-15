# SIEM Home Lab

A small home lab where I set up Wazuh (an open-source SIEM/XDR platform), connected it to a Windows machine, and simulated both local and network-based failed login attempts to practice detecting and analyzing security events — the kind of work a SOC analyst does day to day.

## Background

I have about a year of experience in IT Support and I'm currently moving toward a career in cybersecurity (completing the Google Cybersecurity Professional Certificate). I built this lab to get hands-on experience with a real SIEM tool instead of just reading about how one works.

## Lab Architecture

The lab has three machines, all on the same local network:

- **Wazuh Server** (192.168.1.12) — Linux VM running Wazuh. This is the SIEM, it collects and analyzes logs from the other machines.
- **Windows PC** (192.168.1.3) — my own Windows 11 machine, set up as the monitored endpoint (the "victim").
- **Parrot OS** (192.168.1.13) — a Linux VM playing the role of the attacker.

All three are on the same network (VirtualBox, Bridged mode), so the Wazuh server sees activity from Parrot the same way it would see traffic from any other device on a real network.

## Part 1 — Setup & Local Login Testing

### Setting up the Wazuh server

I downloaded the official Wazuh OVA and imported it into VirtualBox. It already comes with the three main Wazuh components installed: the server (analyzes logs and creates alerts), the indexer (stores the alerts), and the dashboard (the web interface I used to see everything).

![Wazuh dashboard running](screenshots/01-dashboard-working.png)

### Problem: the disk filled up

The default disk on the OVA is 25GB. Not long after starting the VM, the dashboard started showing errors saying the disk usage had exceeded a safety threshold  and new data couldnt be written.


I ran `df -h` and saw the disk was at 100% (25G used, only 39M free). Turns out the indexer blocks writing to disk once it gets too full, as a safety measure, which is why the dashboard couldn't set up its index patterns.

To fix it:
1. Shut down the VM and resized the virtual disk from 25GB to 50GB in VirtualBox.
2. Grew the partition inside the VM: `sudo growpart /dev/sda 1`
3. Grew the filesystem: `sudo xfs_growfs /`
4. Rebooted the VM.

After that, `df -h /` showed the disk at 31% usage, and the dashboard loaded fine.

### Installing the Windows agent

From the dashboard, I used "Deploy new agent" to get a PowerShell command for installing the agent on my Windows PC, pointing it to the Wazuh server (192.168.1.12). After running it, I started the service:

```powershell
NET START Wazuh
```

![Agent install command and service running](screenshots/02-agent-running.png)

At first the agent showed up as **Pending**:

![Agent pending](screenshots/03-agent-pending.png)

A minute or two later, it switched to **Active** and started sending data (system info, a CIS security benchmark scan, etc.).

![Agent active in Wazuh](screenshots/04-agent-active.png)

![Agent overview page](screenshots/05-agent-overview.png)

### Analyzing the first failed login (local)

To generate a test event, I locked my Windows screen and entered the wrong PIN a few times before logging in normally. A minute later, I found the matching alert in Wazuh under **Threat Hunting → Events**:

![Threat hunting dashboard](screenshots/06-threat-hunting-dashboard.png)

![Local failed login event](screenshots/07-event-details.png)

Key fields in the event:

- `rule.description`: Logon Failure - Unknown user or bad password
- `data.win.eventdata.logonType`: 2 (Interactive — typed directly on the machine)
- `data.win.eventdata.ipAddress`: 127.0.0.1 (localhost, confirming it wasn't a network login)
- `data.win.eventdata.status`: 0xC000006D
- `data.win.eventdata.subStatus`: 0xC000006A

I wasn't sure exactly what the status/subStatus codes meant, so I looked them up in Microsoft's documentation for Windows event 4625:

![Status code 0xC000006D](screenshots/status.png)
![Substatus code 0xC000006A](screenshots/substatus.png)

- `0xC000006D` = **STATUS_LOGON_FAILURE** — a general logon failure.
- `0xC000006A` = **STATUS_WRONG_PASSWORD** — the account exists, but the password was wrong.

Since the target account (`targetUserName`) matched my own local account, this confirmed the event was exactly what I expected: a harmless, self-caused failed login — not something to escalate. But it also showed me what a legitimate SOC analyst workflow looks like: don't just read the alert description, check the account, the source, the logon type, and verify anything you're not 100% sure about.

## Part 2 — Network Attack Simulation (SSH)

The first test was local (logon type 2, from 127.0.0.1). To see what a *network-based* failed login looks like, I set up a second scenario using the Parrot OS VM as an "attacker" trying to log in to my Windows PC over the network.

### Setting up the network

Parrot was initially set to NAT mode in VirtualBox, which gave it an internal-only address (10.0.2.15) that couldn't reach the other machines. I switched it to Bridged mode, the same as the Wazuh server, so it would get a real address on the local network.

![Parrot set to Bridged mode](screenshots/08-parrot-bridged.png)

![Parrot's new IP address](screenshots/09-parrot-ip.png)

### Enabling SSH on Windows (temporarily)

Windows 11 Home doesn't support an RDP server, so I used OpenSSH Server instead, which is available as an optional Windows feature. I enabled it just for this test:

```powershell
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
Start-Service sshd
```

![SSH service running](screenshots/10-ssh-service-running.png)

The Windows Firewall already had an inbound rule for it, scoped to the **Private** network profile only:

![SSH firewall rule](screenshots/11-ssh-firewall.png)

My network adapter was set to "Public" in Windows, which silently blocked the connection at first (an RDP test earlier also timed out for the same reason). I switched it to "Private":

![Network set to Private](screenshots/12-private-network.png)

### Running the test

From Parrot, I tried to SSH into my Windows account with the wrong password, three times:

```bash
ssh -o ConnectTimeout=5 User@192.168.1.3
```

![Failed SSH login attempts from Parrot](screenshots/13-ssh-failed-attempts.png)

### Analyzing the network-based failed login

Back in Wazuh, I found the matching events — three more "Logon Failure" alerts, generated at the same time as the SSH attempts:

![SSH login failure event in Wazuh](screenshots/14-ssh-event-details.png)

This time, the key fields were different:

- `data.win.eventdata.logonType`: 8 (NetworkCleartext, used by SSH password auth)
- `data.win.eventdata.processName`: `C:\Windows\System32\OpenSSH\sshd.exe` — confirming the login attempt came through the SSH service, not the normal Windows logon screen
- `data.win.eventdata.status` / `subStatus`: the same 0xC000006D / 0xC000006A as before (wrong password)

One thing I noticed: the `ipAddress` field was empty this time, unlike the local test. It looks like Windows doesn't always populate that field correctly for SSH logons — the `workstationName` field also just showed my own PC's name instead of Parrot's.

To confirm the real source IP, I checked OpenSSH's own logs instead:

```powershell
Get-WinEvent -LogName "OpenSSH/Operational" -MaxEvents 20
```

![OpenSSH log showing Parrot's IP](screenshots/15-openssh-log.png)

This showed exactly what I needed: `sshd: Failed password for User from 192.168.1.13 port 46252 ssh2`, repeated three times, matching the attempts from Parrot. This was a good reminder that a single log source doesn't always have everything — checking the service's own logs filled in the gap that the Windows Security log left blank.

### Cleaning up

Once I was done testing, I stopped and disabled the SSH service so it wouldn't stay exposed:

```powershell
Stop-Service sshd
Set-Service sshd -StartupType Disabled
```

![SSH service stopped](screenshots/16-ssh-closed.png)

## What I Learned

- How a SIEM actually works end to end: agent → server → indexer → dashboard, and how to read an alert beyond just its description.
- The difference between a local and a network-based login attempt, and which fields (`logonType`, `processName`, `ipAddress`) actually tell you that.
- That logs aren't always complete — when one field was missing, I had another source (the SSH service's own logs) to cross-check.
- Basic troubleshooting under pressure: disk space issues, VirtualBox networking modes (NAT vs Bridged), and Windows network profiles (Public vs Private) all got in the way at some point, and I had to figure out why.

## Tools Used

- [Wazuh](https://wazuh.com/) (SIEM/XDR)
- VirtualBox
- Windows 11, PowerShell, OpenSSH Server
- Parrot OS
