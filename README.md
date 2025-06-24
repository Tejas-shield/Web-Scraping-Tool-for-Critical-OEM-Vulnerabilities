🔐 Vulnerability Scanner with Threat Intelligence & Email Alerts
📌 Overview
This project is a Python-Django-based vulnerability scanner that automatically fetches recent vulnerabilities from the National Vulnerability Database (NVD), enriches them using Threat Intelligence APIs like CIRCL and VirusTotal, and sends real-time alerts via email for critical security threats.

Designed for security teams, system administrators, and researchers who want to stay ahead of newly disclosed high-risk vulnerabilities (CVEs).

🚀 Features
✅ Vulnerability Scraping
Pulls CVEs published in the last 30 days from the NVD API

Extracts CVE ID, severity, CVSS score, source, and reference link

📩 Email Alerts
Sends email notifications for CRITICAL vulnerabilities

Alerts contain enriched information: summary, affected products, and risk insights

🧠 Threat Intelligence Enrichment
CIRCL API: Provides summaries, product names, CVSS scores, and references

VirusTotal API: Adds VT Risk Score and exploit data (if available)

🗃 Django ORM & Model
Saves all scanned vulnerabilities in the database

Prevents duplicates using title and supports querying critical CVEs
