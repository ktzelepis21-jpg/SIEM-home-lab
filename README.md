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
