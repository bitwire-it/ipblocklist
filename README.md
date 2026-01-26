# IP Blocklist

![GitHub Repo stars](https://img.shields.io/github/stars/bitwire-it/ipblocklist)

<a href="https://www.buymeacoffee.com/Matis7" target="_blank"><img src="https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png" alt="Buy Me A Coffee" style="height: 41px !important;width: 174px !important;box-shadow: 0px 3px 2px 0px rgba(190, 190, 190, 0.5) !important;-webkit-box-shadow: 0px 3px 2px 0px rgba(190, 190, 190, 0.5) !important;" ></a>

This project provides aggregated IP blocklists for inbound and outbound traffic, updated every 2 hours. It includes exclusions for major public DNS resolvers to prevent legitimate services from being blocked.

---

## Live Statistics

[Live Dashboard](https://bitwire.it/blocklist-stats)

---

## How to Use These Lists

These are standard text files and can be used with most modern firewalls, ad-blockers, and security tools.

### 🛡️ `inbound.txt` (Inbound Blocklist)

* **What it is:** A list of IPs/networks with a bad reputation for *initiating* malicious connections. This includes sources of spam, scanning, brute-force attacks (SSH, RDP), and web exploits.
* **Use Case:** Protect your public-facing servers and services (web servers, mail servers, game servers, etc.).
* **How to use:** Apply this list to your firewall's **WAN IN** or **INPUT** chain to **DROP** or **REJECT** all incoming traffic *from* these sources.

### ☢️ `outbound.txt` (Outbound Blocklist)

* **What it is:** A list of known malicious destination IPs. This includes C2 (Command & Control) servers, botnet controllers, malware drop sites, and phishing hosts.
* **Use Case:** Prevent compromised devices on your *internal* network (like a laptop or IoT device) from *contacting* malicious servers.
* **How to use:** Apply this list to your firewall's **LAN OUT** or **OUTPUT** chain to **BLOCK** or **LOG** all outgoing traffic *to* these destinations.

---

## Self-hosted runners

The workflow `update.yml` take a lot of time to complete, for this reason i started a Self-hoster runner to pick up the job, if you want to setup the action please add it to your forked repository
[Setup Self-hosted runners](https://docs.github.com/en/actions/how-tos/manage-runners/self-hosted-runners/add-runners)

---

## Acknowledgements

🪨 **[borestad](https://www.github.com/borestad)** • *foundational blocklists* 🚀 **Code contributions**
- [David](https://github.com/dvdctn)
- [Garrett Laman](https://github.com/garrettlaman)

❤️ **Our sponsors** • *making this project possible*
- [mraxu](https://www.github.com/mraxu)
- Hareen
- Alexandru Balmus
- blockstreamtechnologies.llc

## License

### Code
The source code (including `update_tables.py`) is licensed under the **MIT License**. See [LICENSE](LICENSE) for details.

### Data
The aggregated blocklists (`inbound.txt`, `outbound.txt`, etc.) are derivative works containing data from multiple sources. 

**Usage of these lists is subject to the licenses of the original data providers.** - Many sources (e.g., Spamhaus) **prohibit commercial use** of their data without a separate agreement.
- Therefore, the aggregated data in this repository is provided under the **Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International (CC BY-NC-SA 4.0)** license.

**Attribution:**
This project relies on data from:

- [borestad/blocklist-abuseipdb](https://github.com/borestad/blocklist-abuseipdb)
- [borestad/firehol-mirror](https://github.com/borestad/firehol-mirror)
- [stamparm/ipsum](https://github.com/stamparm/ipsum)
- [ShadowWhisperer/IPs](https://github.com/ShadowWhisperer/IPs)
- [romainmarcoux/malicious-ip](https://github.com/romainmarcoux/malicious-ip)
- [romainmarcoux/malicious-outgoing-ip](https://github.com/romainmarcoux/malicious-outgoing-ip)
- [elliotwutingfeng/ThreatFox-IOC-IPs](https://github.com/elliotwutingfeng/ThreatFox-IOC-IPs)
- [binarydefense.com](https://www.binarydefense.com/banlist.txt)
- [bruteforceblocker.com](https://danger.rulez.sk/projects/bruteforceblocker/blist.php)
- [darklist.de](https://www.darklist.de/raw.php)
- [dan.me.uk Tor List](https://www.dan.me.uk/torlist/)
- [Emerging Threats](http://rules.emergingthreats.net/blockrules/compromised-ips.txt)
- [Spamhaus DROP](https://www.spamhaus.org/drop/drop.txt)
- [CINSscore](https://cinsscore.com/list/ci-badguys.txt)
- [CriticalPathSecurity](https://github.com/CriticalPathSecurity/Public-Intelligence-Feeds)
- [C2 Tracker](https://github.com/montysecurity/C2-Tracker)

---
