# 🌐 WebRecon — Website Reconnaissance Tool

> Gather everything about a website in seconds.
> DNS, IPs, open ports, SSL cert, HTTP headers, subdomains, geolocation — all in one command.

![Python](https://img.shields.io/badge/Python-3.x-blue?style=flat-square&logo=python&logoColor=white)
![No Dependencies](https://img.shields.io/badge/Dependencies-None-brightgreen?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=flat-square)

---

## ⚡ What It Does

| Module | What You Get |
|--------|-------------|
| 🔍 **DNS & IP**       | IP address, reverse DNS, all IPs |
| 🌍 **Geolocation**    | Country, city, ISP, ASN, coordinates |
| 🔓 **Port Scanner**   | 15 common ports — FTP, SSH, HTTP, RDP... |
| 📋 **HTTP Headers**   | Server info, tech stack, security headers |
| 🔒 **SSL Certificate**| Issuer, expiry date, SANs / alt domains |
| 🕵️ **Subdomains**    | Checks 18 common subdomains automatically |

---

## 🚀 Quick Start

```bash
# Clone
git clone https://github.com/rishellevarghees/WebRecon.git
cd WebRecon

# Run (interactive mode)
python webrecon.py

# Or pass a domain directly
python webrecon.py google.com
python webrecon.py github.com
python webrecon.py example.com
```

**No pip install needed** — uses Python standard library only ✅

---

## 📸 Sample Output

```
╔══════════════════════════════════════════════════════╗
║           WebRecon — Website Recon Tool              ║
╚══════════════════════════════════════════════════════╝

  Target  : google.com
  Started : 2026-03-25 01:00:00

──────────────────────────────────────────────────────
  [ DNS & IP Information ]
──────────────────────────────────────────────────────
  ✔  Domain                 google.com
  ✔  IP Address             142.250.185.14
  ✔  Reverse DNS            lax17s55-in-f14.1e100.net

──────────────────────────────────────────────────────
  [ IP Geolocation ]
──────────────────────────────────────────────────────
  ✔  Country                United States
  ✔  City                   Mountain View
  ✔  ISP                    Google LLC

──────────────────────────────────────────────────────
  [ Open Ports ]
──────────────────────────────────────────────────────
  ✔  80     OPEN    [HTTP]
  ✔  443    OPEN    [HTTPS]

──────────────────────────────────────────────────────
  [ SSL Certificate ]
──────────────────────────────────────────────────────
  ✔  Common Name            *.google.com
  ✔  Issued By              Google Trust Services
  ✔  Valid Until            Jun 16 08:23:23 2026 GMT

  ✔ Recon complete in 4.2s
```

---

## 🛡️ Disclaimer

> This tool is for **educational and authorized testing only**.
> Only scan websites you **own** or have **explicit permission** to test.
> The author is **not responsible** for any misuse.

---

## 👤 Author

**Original author:** Mosaab Afrit

---

## ⭐ Support

If this tool helped you, please consider giving it a **star** ⭐
