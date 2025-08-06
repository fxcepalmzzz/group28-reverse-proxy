# Group 28 – Reverse Proxy Security Project

**Mastering Reverse Proxies for Web Server Protection**

This project was developed to address modern web security threats such as denial-of-service (DoS) attacks, injection payloads, and automated scanning. It implements a secure reverse proxy system enhanced with a Web Application Firewall (WAF), HTTPS, and a custom threat monitoring dashboard to improve the security and visibility of public-facing web infrastructure.

## Project Overview

The reverse proxy system was deployed in a simulated enterprise environment using six virtual machines:

- NGINX reverse proxy (with WAF, HTTPS, bot protection, rate limiting)
- Two Apache backend servers (load-balanced)
- Windows Server 2022 (Domain Controller and Enterprise Certificate Authority)
- Windows 11 Client (for HTTPS verification and testing)
- Kali Linux Attacker (for simulated threats)

All components were manually configured and tested using real-world scenarios.

## Key Features

- NGINX load balancing using round-robin strategy
- HTTPS with certificates issued by a Windows Enterprise CA
- ModSecurity WAF with the OWASP Core Rule Set (CRS)
- Bot protection using user-agent filtering
- Rate limiting per client IP
- Streamlit-based Python dashboard with:
  - Real-time log parsing from access and audit logs
  - Machine learning anomaly detection using Isolation Forest
  - Threat hunting with regex filtering and ML scoring
  - Local AI assistant powered by TinyLlama

## Simulated Attacks and Testing

- SQL Injection and Cross-Site Scripting (XSS) attacks blocked by ModSecurity
- Malicious user agents blocked by bot protection logic
- Denial-of-service behavior tested using Slowloris and R.U.D.Y tools
- All attack attempts verified through logs and dashboard alerts


## Setup Summary

Refer to `setup_docs/instructions.md` for further details.


## Outcome

The final result is a working reverse proxy system with full security monitoring and automated detection. It supports HTTPS, blocks common web attacks, and includes a custom-built dashboard for SOC-style visibility. All components were manually developed and validated in a controlled test environment.

