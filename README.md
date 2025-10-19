# IP Blocklist

![GitHub Repo stars](https://img.shields.io/github/stars/bitwire-it/ipblocklist)

<a href="https://www.buymeacoffee.com/Matis7" target="_blank"><img src="https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png" alt="Buy Me A Coffee" style="height: 41px !important;width: 174px !important;box-shadow: 0px 3px 2px 0px rgba(190, 190, 190, 0.5) !important;-webkit-box-shadow: 0px 3px 2px 0px rgba(190, 190, 190, 0.5) !important;" ></a>

This project provides aggregated IP blocklists for inbound and outbound traffic, updated every 2 hours. It includes exclusions for major public DNS resolvers to prevent legitimate services from being blocked.

---

## Live Statistics

![Inbound IPs](https://img.shields.io/badge/Inbound_IPs-20.6M-red?style=flat-square) ![Outbound IPs](https://img.shields.io/badge/Outbound_IPs-135.0K-orange?style=flat-square) ![Total IPs](https://img.shields.io/badge/Total_IPs-20.7M-blue?style=flat-square) ![Last Updated](https://img.shields.io/badge/Last_Updated-2025--10--19-green?style=flat-square)

- **Inbound Blocklist**: 1,525,695 networks/IPs covering 20,563,506 individual IP addresses
- **Outbound Blocklist**: 135,648 networks/IPs covering 135,028 individual IP addresses
- **Total Coverage**: 20,698,534 individual IP addresses

## Files

- `inbound.txt` - Processed inbound IP blocklist
- `outbound.txt` - Processed outbound IP blocklist

## Acknowledgements

🪨 **[borestad](https://www.github.com/borestad)** • *foundational blocklists*  
🚀 **Code contributions**
- [David](https://github.com/dvdctn)
- [Garrett Laman](https://github.com/garrettlaman)

❤️ **Our sponsors** • *making this project possible*
- [mraxu](https://www.github.com/mraxu)
- Hareen
- Alexandru Balmus

## Data Sources

This blocklist is aggregated from the following reputable sources:

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
- [Talos Intelligence](https://talosintelligence.com/documents/ip-blacklist)
- [CriticalPathSecurity](https://github.com/CriticalPathSecurity/Public-Intelligence-Feeds)
- [C2 Tracker](https://github.com/montysecurity/C2-Tracker)

---

*This README is automatically updated by the update script on 2025-10-19 01:47:15 UTC.*
