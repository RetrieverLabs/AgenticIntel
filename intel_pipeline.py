import os
import json
import time
import random
import re
import smtplib
from email.message import EmailMessage
import feedparser
import requests
import trafilatura
from groq import Groq
from pydantic import BaseModel, Field

# Configuration: Threat Intel RSS Feeds & FYI Feed Sources
FEEDS = [
    "https://www.cisa.gov/cybersecurity-advisories/all.xml",
    "https://www.bleepingcomputer.com/feed/",
    "https://feeds.feedburner.com/TheHackersNews",
]

FYI_FEEDS = [
    {"name": "Google Cloud Threat Intel", "url": "https://cloudblog.withgoogle.com/topics/threat-intelligence/rss/"},
    {"name": "Wiz Cloud Threat Landscape", "url": "https://www.wiz.io/api/feed/cloud-threat-landscape/rss.xml"},
    {"name": "Dark Reading", "url": "https://www.darkreading.com/rss.xml"},
    {"name": "SecurityWeek", "url": "https://www.securityweek.com/feed/"},
    {"name": "Microsoft Security", "url": "https://www.microsoft.com/en-us/security/blog/feed/"},
]

SEEN_FILE = "seen_urls.json"
PDF_FILENAME = "agentic_threat_intel_digest.pdf"

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36"
]

if os.path.exists(SEEN_FILE):
    with open(SEEN_FILE, "r") as f:
        seen_data = json.load(f)
else:
    seen_data = {"seen": []}

seen_urls = set(seen_data["seen"])

KEYWORDS = [
    "critical", "cvss 9", "cvss 10", "rce", "remote code execution",
    "zero-day", "0-day", "actively exploited", "ransomware", "supply chain",
    "banking", "financial", "payment", "authentication bypass", "auth bypass",
    "vmware", "citrix", "palo alto", "cisco", "f5", "ivanti", "active directory"
]

def undefang_text(text: str) -> str:
    """Robust undefanging normalization for threat intel IOCs and text."""
    if not text:
        return ""
    text = re.sub(r'hxxps?://', lambda m: m.group(0).replace('hxxp', 'http'), text, flags=re.IGNORECASE)
    text = text.replace('[.]', '.').replace('(.)', '.').replace('[dot]', '.').replace('(dot)', '.')
    text = text.replace('[:]', ':')
    return text

def get_latest_unit42_ioc_feed():
    api_url = "https://api.github.com/repos/PaloAltoNetworks/Unit42-timely-threat-intel/contents/"
    headers = {"Accept": "application/vnd.github.v3+json"}
    try:
        response = requests.get(api_url, headers=headers, timeout=10)
        if response.status_code == 200:
            files = response.json()
            txt_files = [f for f in files if f["name"].endswith(".txt")]
            if not txt_files:
                return None, None
            txt_files.sort(key=lambda x: x["name"])
            latest_file = txt_files[-1]
            print(f"[*] Discovered latest Unit 42 IOC file: {latest_file['name']}")
            file_resp = requests.get(latest_file["download_url"], timeout=10)
            if file_resp.status_code == 200:
                return latest_file["name"], undefang_text(file_resp.text)
    except Exception as e:
        print(f"    [!] Error polling GitHub repository: {e}")
    return None, None

# --- 1. Gather FYI News Table Data ---
print("[*] Gathering recent headlines from FYI feeds...")
fyi_table_rows = []
for feed_info in FYI_FEEDS:
    try:
        parsed = feedparser.parse(feed_info["url"])
        for entry in parsed.entries[:3]:
            title = getattr(entry, "title", "Unknown Title").strip()
            summary = getattr(entry, "summary", getattr(entry, "description", "No summary available."))
            summary_clean = re.sub('<[^<]+?>', '', summary).strip()
            one_liner = (summary_clean[:90] + '...') if len(summary_clean) > 90 else summary_clean
            fyi_table_rows.append({
                "feed": feed_info["name"],
                "title": title,
                "summary": one_liner or "Recent security advisory update."
            })
    except Exception as e:
        print(f"    [!] Error fetching FYI feed {feed_info['name']}: {e}")

# --- 2. Gather Core Actionable Threats ---
new_articles = []

for feed_url in FEEDS:
    parsed_feed = feedparser.parse(feed_url)
    for entry in parsed_feed.entries[:5]:
        link = getattr(entry, "link", "")
        title = getattr(entry, "title", "")
        pub_date = getattr(entry, "published", getattr(entry, "updated", "Unknown Date"))
        if not link or link in seen_urls:
            continue
        text_blob = f"{title} {getattr(entry, 'summary', '')}".lower()
        if any(kw in text_blob for kw in KEYWORDS):
            if any(ot_kw in text_blob for ot_kw in ["siemens", "ruggedcom", "gridscale", "desigo", "scada", "ics", "plc", "manufacturing"]):
                continue
            new_articles.append({"title": title, "link": link, "pub_date": pub_date, "type": "rss"})

# Dynamically poll GitHub Unit 42 feed
filename, raw_content = get_latest_unit42_ioc_feed()
if filename and raw_content:
    gh_link = f"https://github.com/PaloAltoNetworks/Unit42-timely-threat-intel/blob/main/{filename}"
    if gh_link not in seen_urls:
        ips = list(set(re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', raw_content)))
        domains = list(set(re.findall(r'\b(?:[a-zA-Z0-9][-a-zA-Z0-9]*\.)+[a-zA-Z]{2,}\b', raw_content)))
        urls = list(set(re.findall(r'https?://[^\s]+', raw_content)))
        sha256s = list(set(re.findall(r'\b[a-fA-F0-9]{64}\b', raw_content)))
        paths = list(set(re.findall(r'(?:%[A-Z]+%|\/[a-zA-Z0-9_\-\.]+)(?:\\[a-zA-Z0-9_\-\.]+)+', raw_content)))
        
        new_articles.append({
            "title": f"Unit 42 Threat Campaign IOC Feed ({filename})",
            "link": gh_link,
            "pub_date": filename[:10],
            "type": "github_ioc",
            "raw_iocs": {"ips": ips, "domains": domains, "urls": urls, "sha256s": sha256s, "paths": paths, "raw_text": raw_content[:4000]}
        })

client = Groq(api_key=os.environ.get("GROQ_API_KEY"))

class ThreatAnalysis(BaseModel):
    threat_date: str = Field(description="Date reported or observed (YYYY-MM-DD)")
    severity: str = Field(description="CRITICAL, HIGH, MEDIUM, or LOW")
    exec_summary: str = Field(description="One-liner executive summary")
    is_new_campaign: str = Field(description="'New' or 'Seen Before / Variant'")
    threat_group: str = Field(description="Attribution threat actor or 'Unknown'")
    affected_tech_cves: str = Field(description="Impacted software and CVE IDs or extracted IOC summary")
    exploitation_status: str = Field(description="e.g., 'Actively Exploited in the Wild', 'PoC Public'")
    scope_impact: str = Field(description="Brief scope and financial/enterprise impact")
    countries_industries: str = Field(description="Impacted sectors (Canada, US, UK financial focus)")
    mitre_ttps: str = Field(description="Key MITRE ATT&CK IDs and names")
    recommended_action: str = Field(description="Concrete remediation action")
    logscale_queries: list[str] = Field(description="LogScale queries covering Endpoint, Web, and Network Traffic telemetry")
    splunk_queries: list[str] = Field(description="Splunk queries covering Endpoint, Web.Web, and Network_Traffic.All_Traffic datamodels")

reports = []

for i, item in enumerate(new_articles, 1):
    seen_urls.add(item["link"])
    print(f"\n[*] Processing [{i}/{len(new_articles)}]: {item['title']}")
    
    if item["type"] == "github_ioc":
        article_text = f"GitHub IOC Feed Data:\nURLs: {item['raw_iocs']['urls']}\nHashes: {item['raw_iocs']['sha256s']}\nPaths: {item['raw_iocs']['paths']}\nIPs: {item['raw_iocs']['ips']}\nDomains: {item['raw_iocs']['domains']}\n\nRaw Excerpt:\n{item['raw_iocs']['raw_text']}"
    else:
        headers = {"User-Agent": random.choice(USER_AGENTS)}
        try:
            resp = requests.get(item["link"], headers=headers, timeout=10)
            downloaded = resp.text if resp.status_code == 200 else None
        except:
            downloaded = None
        article_text = trafilatura.extract(downloaded) if downloaded else item["title"]
        if not article_text:
            article_text = item["title"]

    system_prompt = (
        "You are an expert cyber security threat intelligence analyst and threat hunter for Agentic Finance. "
        "Analyze the provided threat data and return valid JSON matching the required schema. "
        "Ensure production-ready SIEM queries cover CrowdStrike LogScale and Splunk across Endpoint, Web (Web.Web), and Network Traffic (Network_Traffic.All_Traffic) data models."
    )

    user_prompt = (
        f"Analyze this threat intelligence item for SOC threat hunters.\n"
        f"Title: {item['title']}\nSource URL/Feed: {item['link']}\n"
        f"Content/IOCs:\n{article_text[:4500]}"
    )

    try:
        response_obj = client.chat.completions.create(
            model="openai/gpt-oss-120b",
            messages=[
                {"role": "system", "content": system_prompt + f"\n\nReturn ONLY valid JSON matching schema: {ThreatAnalysis.model_json_schema()}"},
                {"role": "user", "content": user_prompt}
            ],
            response_format={"type": "json_object"},
            temperature=0.1
        )
        data = json.loads(response_obj.choices[0].message.content)
        severity = data.get('severity', '').strip().upper()
        
        if severity not in ["CRITICAL", "HIGH"]:
            continue

        logscale_joined = "\n\n".join(data.get('logscale_queries', []))
        splunk_joined = "\n\n".join(data.get('splunk_queries', []))

        report_text = (
            "======================================================================\n" +
            "[" + severity + "] THREAT INTEL BRIEFING: " + str(item.get('title', '')) + "\n" +
            "======================================================================\n" +
            "• Threat Date        : " + str(data.get('threat_date', '')) + "\n" +
            "• Executive Summary  : " + str(data.get('exec_summary', '')) + "\n" +
            "• Campaign Status    : " + str(data.get('is_new_campaign', '')) + "\n" +
            "• Threat Actor       : " + str(data.get('threat_group', '')) + "\n" +
            "• Affected Tech/IOCs : " + str(data.get('affected_tech_cves', '')) + "\n" +
            "• Exploitation State : " + str(data.get('exploitation_status', '')) + "\n" +
            "• Scope & Impact     : " + str(data.get('scope_impact', '')) + "\n" +
            "• Target Sectors     : " + str(data.get('countries_industries', '')) + "\n" +
            "• MITRE ATT&CK       : " + str(data.get('mitre_ttps', '')) + "\n" +
            "• Recommended Action : " + str(data.get('recommended_action', '')) + "\n" +
            "• Source URL         : " + str(item.get('link', '')) + "\n\n" +
            "--- LOGSCALE QUERIES ---\n" + logscale_joined + "\n\n" +
            "--- SPLUNK QUERIES (Endpoint, Web, Network) ---\n" + splunk_joined + "\n" +
            "======================================================================"
        )
        reports.append(report_text)
    except Exception as e:
        print(f"    [!] Error: {e}")

    time.sleep(2.0)

with open(SEEN_FILE, "w") as f:
    json.dump({"seen": list(seen_urls)[-1000:]}, f)

# --- 3. Generate Simple PDF Report for Attachment ---
try:
    from reportlab.lib.pagesizes import letter
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

    doc = SimpleDocTemplate(PDF_FILENAME, pagesize=letter, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36)
    styles = getSampleStyleSheet()
    story = [
        Paragraph("<b>Agentic Threat Intelligence Digest</b>", styles['Heading1']),
        Spacer(1, 10),
        Paragraph(f"Automated threat brief generated for ACME Finance (Canada/US/UK). Total actionable briefings: {len(reports)}", styles['Normal']),
        Spacer(1, 15)
    ]
    
    for r in reports:
        story.append(Paragraph(r.replace('\n', '<br/>'), styles['Code']))
        story.append(Spacer(1, 15))
        
    doc.build(story)
    print(f"[*] Successfully generated {PDF_FILENAME}")
except Exception as pdf_err:
    print(f"    [!] PDF generation note: {pdf_err}")

# --- 4. Construct and Send Email with PDF Attachment ---
if fyi_table_rows or reports:
    print(f"\n[*] Preparing final email digest...")
    email_body_parts = []
    
    if fyi_table_rows:
        email_body_parts.append("======================================================================")
        email_body_parts.append("[FYI LANDSCAPE] RECENT THREAT & SECURITY HEADLINES")
        email_body_parts.append("======================================================================")
        for row in fyi_table_rows:
            email_body_parts.append(f"• [{row['feed']}] {row['title']}\n  Summary: {row['summary']}\n")
        email_body_parts.append("======================================================================\n")

    if reports:
        email_body_parts.extend(reports)
    
    msg = EmailMessage()
    msg['Subject'] = f"[Agentic Threat Intel Digest] Landscape FYI & {len(reports)} Actionable Briefing(s)"
    msg['From'] = os.environ["GMAIL_USER"]
    msg['To'] = os.environ["GMAIL_RECIPIENT"]
    msg.set_content("\n".join(email_body_parts))

    # Attach PDF report if it exists
    if os.path.exists(PDF_FILENAME):
        with open(PDF_FILENAME, "rb") as f:
            pdf_data = f.read()
        msg.add_attachment(
            pdf_data,
            maintype="application",
            subtype="pdf",
            filename=PDF_FILENAME
        )
        print("[*] Attached PDF report to email.")

    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
        smtp.login(os.environ["GMAIL_USER"], os.environ["GMAIL_APP_PASSWORD"])
        smtp.send_message(msg)
    print("[*] Agentic Threat Intel Digest emailed successfully.")
else:
    print("\n[*] No reports generated.")