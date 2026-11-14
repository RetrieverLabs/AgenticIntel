import os
import json
import time
import random
import html
import re
import smtplib
from email.message import EmailMessage
import feedparser
import requests
import trafilatura
from groq import Groq
from pydantic import BaseModel, Field
from datetime import datetime, timedelta

# Configuration: Feeds & Sources
CISA_KEV_FEED = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CCCS_ALERTS_URL = "https://www.cyber.gc.ca/en/alerts-advisories"
WIZ_INCIDENTS_URL = "https://threats.wiz.io/all-incidents"

FEEDS = [
    CISA_KEV_FEED,
    "https://www.bleepingcomputer.com/feed/",
    "https://feeds.feedburner.com/TheHackersNews",
    "https://radar.cloudflare.com/zero-wire/rss"
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

def clean_html_tags(text: str) -> str:
    """Removes HTML tags and normalizes unicode hyphens to prevent black-box rendering bugs."""
    if not text:
        return ""
    text = text.replace('\u2010', '-').replace('\u2011', '-').replace('\u2012', '-').replace('\u2013', '-').replace('\u2014', '-')
    cleaned = re.sub(r'<[^>]+>', '', text)
    return html.escape(cleaned.replace('&', '&amp;'))

def parse_standard_date(date_str: str) -> str:
    """Parses various RSS/Blog date formats into strict YYYY-MM-DD format."""
    if not date_str:
        return datetime.now().strftime("%Y-%m-%d")
    date_str = re.sub(r'\s+(EDT|EST|PDT|PST|UTC|GMT|[+-]\d{4})$', '', date_str).strip()
    
    # Try parsing spelled-out formats like "October 21, 2026"
    try:
        dt = datetime.strptime(date_str, "%B %d, %Y")
        return dt.strftime("%Y-%m-%d")
    except ValueError:
        pass

    formats = [
        "%a, %d %b %Y %H:%M:%S %z",
        "%a, %d %b %Y %H:%M:%S",
        "%d %b %Y %H:%M:%S %z",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%d"
    ]
    for fmt in formats:
        try:
            dt = datetime.strptime(date_str, fmt)
            return dt.strftime("%Y-%m-%d")
        except ValueError:
            continue
    match = re.search(r'(\d{4})[/-](\d{2})[/-](\d{2})', date_str)
    if match:
        return f"{match.group(1)}-{match.group(2)}-{match.group(3)}"
    return datetime.now().strftime("%Y-%m-%d")

def is_within_past_24_hours(date_str: str) -> bool:
    """Checks if a given date string or timestamp falls within the past 24 hours."""
    if not date_str:
        return True
    cleaned_date = parse_standard_date(date_str)
    try:
        target_dt = datetime.strptime(cleaned_date, "%Y-%m-%d")
        cutoff_dt = datetime.now() - timedelta(hours=24)
        return target_dt >= cutoff_dt.replace(hour=0, minute=0, second=0, microsecond=0)
    except Exception:
        return True

def extract_comprehensive_iocs(raw_text: str) -> dict:
    """Extracts, defangs, deduplicates, and sorts IOCs with expanded display limits."""
    clean_text = undefang_text(raw_text)
    
    ips = sorted(list(set(re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', clean_text))))
    domains = sorted(list(set(re.findall(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b', clean_text))))
    urls = sorted(list(set(re.findall(r'https?://[^\s<>"]+', clean_text))))
    sha256s = sorted(list(set(re.findall(r'\b[a-fA-F0-9]{64}\b', clean_text))))
    md5s = sorted(list(set(re.findall(r'\b[a-fA-F0-9]{32}\b', clean_text))))
    paths = sorted(list(set(re.findall(r'(?:%[A-Z]+%|\/[a-zA-Z0-9_\-\.]+)(?:\\[a-zA-Z0-9_\-\.]+)+', clean_text))))
    filenames = sorted(list(set(re.findall(r'\b[a-zA-Z0-9_\-]+\.(?:exe|dll|ps1|sh|py|js|elf|bin|bat|cmd|msi)\b', clean_text, re.IGNORECASE))))
    packages = sorted(list(set(re.findall(r'\b(?:npm|pip|cargo|gem|nuget)\s+install\s+([a-zA-Z0-9_\-]+)', clean_text, re.IGNORECASE))))
    http_traffic = sorted(list(set(re.findall(r'(?:GET|POST|PUT|DELETE)\s+[^\s]+\s+HTTP\/[0-9\.]+', clean_text))))

    return {
        "ips": [i for i in ips if not i.startswith("127.") and not i.startswith("10.")][:20],
        "domains": domains[:25],
        "urls": urls[:15],
        "sha256s": sha256s[:15],
        "md5s": md5s[:15],
        "paths": paths[:15],
        "filenames": filenames[:15],
        "packages": packages[:15],
        "http_traffic": http_traffic[:15]
    }

def get_latest_unit42_ioc_feed():
    api_url = "https://api.github.com/repos/PaloAltoNetworks/Unit42-timely-threat-intel/contents/"
    headers = {"Accept": "application/vnd.github.v3+json"}
    try:
        response = requests.get(api_url, headers=headers, timeout=10)
        if response.status_code == 200:
            files = response.json()
            txt_files = [f for f in files if f["name"].endswith(".txt")]
            if not txt_files:
                return None, None, None
            txt_files.sort(key=lambda x: x["name"])
            latest_file = txt_files[-1]
            file_date = parse_standard_date(latest_file["name"][:10])
            
            if not is_within_past_24_hours(file_date):
                return None, None, None
                
            print(f"[*] Discovered fresh Unit 42 IOC file: {latest_file['name']}")
            file_resp = requests.get(latest_file["download_url"], timeout=10)
            if file_resp.status_code == 200:
                return latest_file["name"], file_date, file_resp.text
    except Exception as e:
        print(f"    [!] Error polling GitHub repository: {e}")
    return None, None, None

def scrape_wiz_incidents():
    """Scrapes active incidents from https://threats.wiz.io/all-incidents and filters for past 24h."""
    print("[*] Scraping Wiz Threat Incidents...")
    wiz_entries = []
    try:
        headers = {"User-Agent": random.choice(USER_AGENTS)}
        resp = requests.get(WIZ_INCIDENTS_URL, headers=headers, timeout=10)
        if resp.status_code == 200:
            html_text = resp.text
            # Regex pattern to match incident rows containing Title and Publication Date
            matches = re.findall(r'<tr>\s*<td>([^<]+)</td>\s*<td>([^<]+)</td>', html_text)
            if not matches:
                # Alternative regex parser for table structures
                matches = re.findall(r'\| ([^|]+) \| ([A-Za-z]+ \d{1,2}, \d{4}) \|', html_text)
                
            seen_wiz = set()
            for title, date_str in matches:
                clean_title = title.strip()
                clean_date = parse_standard_date(date_str.strip())
                if is_within_past_24_hours(clean_date):
                    if clean_title not in seen_wiz and len(clean_title) > 5:
                        seen_wiz.add(clean_title)
                        wiz_entries.append({
                            "title": f"[Wiz Incident] {clean_title}",
                            "link": WIZ_INCIDENTS_URL,
                            "pub_date": clean_date,
                            "type": "wiz_incident",
                            "raw_text": f"Wiz Threat Center Incident: {clean_title} published on {clean_date}"
                        })
    except Exception as e:
        print(f"    [!] Error scraping Wiz incidents: {e}")
    return wiz_entries

def scrape_cccs_alerts():
    """Scrapes latest alerts from CCCS advisories page within past 24 hours."""
    print("[*] Scraping CCCS (Cyber Centre) alerts...")
    cccs_entries = []
    try:
        headers = {"User-Agent": random.choice(USER_AGENTS)}
        resp = requests.get(CCCS_ALERTS_URL, headers=headers, timeout=10)
        if resp.status_code == 200:
            html_text = resp.text
            matches = re.findall(r'href="(/en/alerts-advisories/[^"]+)"[^>]*>([^<]+)</a>.*?(\d{4}-\d{2}-\d{2})', html_text, re.DOTALL)
            seen_cccs = set()
            for path, title, date_str in matches:
                if is_within_past_24_hours(date_str):
                    full_link = f"https://www.cyber.gc.ca{path}"
                    clean_title = title.strip()
                    if full_link not in seen_cccs and len(clean_title) > 10:
                        seen_cccs.add(full_link)
                        cccs_entries.append({
                            "date": date_str,
                            "title": clean_title,
                            "link": full_link
                        })
    except Exception as e:
        print(f"    [!] Error scraping CCCS alerts: {e}")
    return cccs_entries

# --- 1. Gather CCCS Alerts & FYI News Feed Data (24-Hour Filtered) ---
cccs_board = scrape_cccs_alerts()

print("[*] Gathering recent headlines from FYI feeds (past 24h)...")
fyi_entries = []
financial_keywords = ["financial", "banking", "data", "cloud", "payment", "credential", "auth", "breach", "ransomware", "api"]

for feed_info in FYI_FEEDS:
    try:
        parsed = feedparser.parse(feed_info["url"])
        for entry in parsed.entries[:6]:
            raw_date = getattr(entry, "published", getattr(entry, "updated", ""))
            pub_date = parse_standard_date(raw_date)
            
            if not is_within_past_24_hours(pub_date):
                continue
                
            title = getattr(entry, "title", "Unknown Title").strip()
            link = getattr(entry, "link", "#")
            summary = getattr(entry, "summary", getattr(entry, "description", "No summary available."))
            summary_clean = re.sub('<[^<]+?>', '', summary).strip()
            one_liner = (summary_clean[:120] + '...') if len(summary_clean) > 120 else summary_clean
            
            score = sum(1 for kw in financial_keywords if kw in title.lower() or kw in summary_clean.lower())
            
            fyi_entries.append({
                "date": pub_date,
                "feed": feed_info["name"],
                "title": title,
                "link": link,
                "summary": one_liner,
                "score": score
            })
    except Exception as e:
        print(f"    [!] Error fetching FYI feed {feed_info['name']}: {e}")

fyi_entries.sort(key=lambda x: (x["score"], x["date"]), reverse=True)
top_fyi_entries = fyi_entries[:6]

# --- 2. Gather Core Actionable Threats (Strict 24-Hour Window) ---
new_articles = []
existing_titles = set()

# Add scraped Wiz incidents (24h filtered)
wiz_incidents = scrape_wiz_incidents()
for inc in wiz_incidents:
    if inc["link"] not in seen_urls:
        existing_titles.add(inc["title"].lower())
        new_articles.append(inc)

try:
    cf_parsed = feedparser.parse("https://radar.cloudflare.com/zero-wire/rss")
    for entry in cf_parsed.entries[:10]:
        raw_date = getattr(entry, "published", getattr(entry, "updated", ""))
        pub_date = parse_standard_date(raw_date)
        if not is_within_past_24_hours(pub_date):
            continue
        title = getattr(entry, "title", "").strip()
        link = getattr(entry, "link", "")
        summary = getattr(entry, "summary", "")
        if link and link not in seen_urls:
            existing_titles.add(title.lower())
            new_articles.append({
                "title": f"[Zero Wire] {title}",
                "link": link,
                "pub_date": pub_date,
                "type": "rss",
                "raw_text": summary
            })
except Exception as e:
    print(f"    [!] Error parsing Cloudflare Zero Wire feed: {e}")

try:
    kev_resp = requests.get(CISA_KEV_FEED, timeout=15)
    if kev_resp.status_code == 200:
        kev_data = kev_resp.json()
        vulns = kev_data.get("vulnerabilities", [])
        added_count = 0
        for v in vulns:
            date_added_str = v.get("dateAdded", "")
            if not is_within_past_24_hours(date_added_str):
                continue
                
            cve_id = v.get("cveID", "")
            vuln_name = v.get("vulnerabilityName", "")
            short_desc = v.get("shortDescription", "")
            product = v.get("product", "")
            vendor = v.get("vendor", "")
            
            combined_text = f"{cve_id} {vuln_name} {short_desc} {product} {vendor}".lower()
            if not any(kw in combined_text for kw in KEYWORDS) and not any(tech in combined_text for tech in ["vmware", "citrix", "palo alto", "cisco", "f5", "ivanti", "active directory", "postgresql", "apache", "redis", "exchange"]):
                continue
                
            kev_link = f"https://www.cisa.gov/known-exploited-vulnerabilities?search_api_fulltext={cve_id}"
            title = f"CISA KEV Active Exploitation: {cve_id} - {vuln_name}"
            
            if kev_link not in seen_urls and title.lower() not in existing_titles:
                new_articles.append({
                    "title": title,
                    "link": kev_link,
                    "pub_date": date_added_str,
                    "type": "kev",
                    "raw_text": f"Vendor: {vendor} | Product: {product} | Vulnerability: {vuln_name} | Description: {short_desc}"
                })
                added_count += 1
        print(f"[*] Filtered CISA KEV (Past 24h): Added {added_count} relevant vulnerabilities.")
except Exception as e:
    print(f"    [!] Error fetching/filtering CISA KEV JSON: {e}")

for feed_url in FEEDS:
    if "known_exploited_vulnerabilities" in feed_url or "zero-wire" in feed_url:
        continue
    parsed_feed = feedparser.parse(feed_url)
    for entry in parsed_feed.entries[:10]:
        link = getattr(entry, "link", "")
        title = getattr(entry, "title", "").strip()
        raw_date = getattr(entry, "published", getattr(entry, "updated", ""))
        pub_date = parse_standard_date(raw_date)
        
        if not is_within_past_24_hours(pub_date):
            continue
            
        if not link or link in seen_urls or title.lower() in existing_titles:
            continue
            
        text_blob = f"{title} {getattr(entry, 'summary', '')}".lower()
        if any(kw in text_blob for kw in KEYWORDS):
            if any(ot_kw in text_blob for ot_kw in ["siemens", "ruggedcom", "gridscale", "desigo", "scada", "ics", "plc", "manufacturing"]):
                continue
            new_articles.append({"title": title, "link": link, "pub_date": pub_date, "type": "rss"})

filename, file_date, raw_content = get_latest_unit42_ioc_feed()
if filename and raw_content:
    gh_link = f"https://github.com/PaloAltoNetworks/Unit42-timely-threat-intel/blob/main/{filename}"
    if gh_link not in seen_urls:
        new_articles.append({
            "title": f"Unit 42 Threat Campaign IOC Feed ({filename})",
            "link": gh_link,
            "pub_date": file_date,
            "type": "github_ioc",
            "raw_text": raw_content
        })

client = Groq(api_key=os.environ.get("GROQ_API_KEY"))

class StrategicThreatAnalysis(BaseModel):
    threat_date: str = Field(description="Exact publication date provided in context in strict YYYY-MM-DD format")
    severity: str = Field(description="CRITICAL, HIGH, MEDIUM, or LOW")
    exec_summary: str = Field(description="Concise 1-2 sentence executive summary for leadership")
    threat_group: str = Field(description="Attribution threat actor or 'Unknown'")
    affected_tech_cves: str = Field(description="Clean bulleted summary string (using • prefix for each point) of impacted software and CVE IDs")
    exploitation_status: str = Field(description="e.g., 'Actively Exploited in the Wild', 'PoC Public'")
    scope_impact: str = Field(description="Clean bulleted summary string (using • prefix for each point) mapping impact to specific telemetry sources (e.g., • WAF Logs / Perimeter Gateway, • PostgreSQL Audit Logs, • CrowdStrike Endpoint)")
    mitre_ttps: str = Field(description="Clean bulleted summary string (using • prefix for each point) of key MITRE ATT&CK TTP IDs and names")
    hunting_hypothesis: str = Field(description="Clean bulleted summary string (using • prefix for each point) outlining where to look in telemetry")
    successful_exploit_profile: str = Field(description="Clean bulleted summary string (using • prefix for each point) detailing the exploitation chain")
    sample_hunt_query: str = Field(description="A concrete sample LogScale or SPL query snippet explicitly incorporating extracted domains, IPs, or indicators from the context.")

reports = []

for i, item in enumerate(new_articles, 1):
    seen_urls.add(item["link"])
    print(f"\n[*] Processing [{i}/{len(new_articles)}]: {item['title']}")
    
    if item["type"] in ["github_ioc", "kev", "wiz_incident"] or "raw_text" in item:
        article_text = item.get("raw_text", item["title"])
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

    extracted_iocs = extract_comprehensive_iocs(article_text)

    system_prompt = (
        "You are a Principal Cyber Threat Hunter and Threat Intelligence Lead for a major financial institution. "
        "Analyze the provided intelligence, ensure publication date is in strict YYYY-MM-DD format, "
        "format all multi-item fields using clean bullet points starting with '• ' and separate points with '\\n', "
        "explicitly map enterprise scope and impact to specific telemetry sources (e.g., WAF, CloudTrail, CrowdStrike, PostgreSQL logs), "
        "provide a sample LogScale/SPL hunting query that incorporates extracted domains, IPs, or specific IOC indicators from the text, "
        "and map actions to MITRE ATT&CK TTPs. Discard or rate as 'LOW' severity any ICS/OT/manufacturing advisories."
    )

    user_prompt = (
        f"Analyze this threat intelligence item:\n"
        f"Title: {item['title']}\n"
        f"Source URL: {item['link']}\n"
        f"Publication Date (USE THIS EXACT DATE): {item['pub_date']}\n\n"
        f"Content/Context:\n{article_text[:4500]}"
    )

    # Robust Retry Loop for Groq 429 TPM Rate Limit Mitigation
    success = False
    for attempt in range(4):
        try:
            response_obj = client.chat.completions.create(
                model="openai/gpt-oss-120b",
                messages=[
                    {"role": "system", "content": system_prompt + f"\n\nReturn ONLY valid JSON matching schema: {StrategicThreatAnalysis.model_json_schema()}"},
                    {"role": "user", "content": user_prompt}
                ],
                response_format={"type": "json_object"},
                temperature=0.1
            )
            data = json.loads(response_obj.choices[0].message.content)
            success = True
            break
        except Exception as api_err:
            backoff = 4.0 * (attempt + 1)
            print(f"    [!] Groq API Rate Limit / Error (Attempt {attempt+1}/4): {api_err}. Pausing {backoff}s...")
            time.sleep(backoff)

    if not success:
        print(f"    [!] Skipping item due to persistent Groq rate limits.")
        continue

    severity = data.get('severity', '').strip().upper()
    print(f"    [+] LLM Assessed Severity: {severity}")
    
    if item["type"] in ["github_ioc", "kev", "wiz_incident"] and severity not in ["CRITICAL", "HIGH"]:
        severity = "HIGH"

    if severity not in ["CRITICAL", "HIGH"]:
        print(f"    [!] Skipping item due to non-critical severity: {severity}")
        continue

    reports.append({
        "title": item.get('title', ''),
        "severity": severity,
        "threat_date": item.get('pub_date', parse_standard_date(data.get('threat_date', ''))),
        "exec_summary": data.get('exec_summary', ''),
        "threat_group": data.get('threat_group', ''),
        "affected_tech_cves": data.get('affected_tech_cves', ''),
        "exploitation_status": data.get('exploitation_status', ''),
        "scope_impact": data.get('scope_impact', ''),
        "mitre_ttps": data.get('mitre_ttps', ''),
        "hunting_hypothesis": data.get('hunting_hypothesis', ''),
        "successful_exploit_profile": data.get('successful_exploit_profile', ''),
        "sample_hunt_query": data.get('sample_hunt_query', ''),
        "iocs": extracted_iocs,
        "link": item.get('link', '')
    })
    print(f"    [+] Successfully added briefing to report queue.")
    time.sleep(3.0) # Additional breathing room between items to stay well under 8K TPM

with open(SEEN_FILE, "w") as f:
    json.dump({"seen": list(seen_urls)[-1000:]}, f)

# --- 3. Generate Executive-Friendly Styled PDF Report with Global Outlook Final Page ---
try:
    import urllib.request
    from reportlab.lib.pagesizes import letter
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable, PageBreak, Image
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib import colors

    PDF_FILENAME = "executive_report.pdf"

    # --- 1. Fetch Live SANS Infocon Data ---
    infocon_level = "Normal"
    try:
        url = "https://isc.sans.edu/infocon.txt"
        with urllib.request.urlopen(url, timeout=3) as response:
            infocon_level = response.read().decode('utf-8').strip().capitalize()
    except Exception:
        pass

    # Map SANS Infocon levels to professional executive colors
    infocon_colors = {
        "Green": "#2F855A",   # Forest Green
        "Yellow": "#D69E2E",  # Amber / Gold
        "Orange": "#DD6B20",  # Dark Orange
        "Red": "#E53E3E"      # Crimson Red
    }
    status_color = infocon_colors.get(infocon_level, "#2D3748")

    # --- 3. Generate Executive-Friendly Styled PDF Report ---
    doc = SimpleDocTemplate(PDF_FILENAME, pagesize=letter, rightMargin=25, leftMargin=25, topMargin=25, bottomMargin=25)
    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        'DocTitle', parent=styles['Heading1'], fontSize=15, leading=18, textColor=colors.HexColor("#1A365D"), spaceAfter=2
    )
    subtitle_style = ParagraphStyle(
        'DocSubTitle', parent=styles['Normal'], fontSize=8, leading=11, textColor=colors.HexColor("#4A5568"), spaceAfter=8
    )
    section_heading = ParagraphStyle(
        'SectionHeading', parent=styles['Heading2'], fontSize=10, leading=13, textColor=colors.HexColor("#2B6CB0"), spaceBefore=8, spaceAfter=3
    )
    cell_style = ParagraphStyle(
        'TableCell', parent=styles['Normal'], fontSize=8, leading=11, textColor=colors.HexColor("#2D3748")
    )
    cell_bold = ParagraphStyle(
        'TableCellBold', parent=styles['Normal'], fontName="Helvetica-Bold", fontSize=8, leading=11, textColor=colors.HexColor("#1A365D")
    )
    code_cell_style = ParagraphStyle(
        'CodeTableCell', parent=styles['Normal'], fontName="Courier", fontSize=7.5, leading=10, textColor=colors.HexColor("#1A202C")
    )

    story = []

    # Ensure reports variable exists safely
    reports = reports if 'reports' in locals() else []

    # Build dynamic subtitle string with colored status
    subtitle_text = (
        f"Target Scope: Canadian Financial Institution (ACME Finance) | "
        f"Briefings: {len(reports)} | "
        f"SANS ISC Infocon: <font color='{status_color}'><b>{infocon_level}</b></font>"
    )

    header_table_data = [
        [
            Paragraph(
                f"<b>Executive Threat Intelligence & Hunting Digest</b><br/>"
                f"<font size=8 color='#4A5568'>{subtitle_text}</font>", 
                title_style
            ),
        ]
    ]

    header_table = Table(header_table_data, colWidths=[420, 120])
    header_table.setStyle(TableStyle([
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('LEFTPADDING', (0,0), (-1,-1), 0),
        ('RIGHTPADDING', (0,0), (-1,-1), 0),
        ('BOTTOMPADDING', (0,0), (-1,-1), 5),
    ]))

    story.append(header_table)
    story.append(HRFlowable(width="100%", thickness=1.2, color=colors.HexColor("#1A365D"), spaceAfter=8))

# Uncomment below when ready to build your full document story

    if cccs_board:
        story.append(Paragraph("<b>CCCS / Cyber Centre Alerts & Advisories (Canada - Past 24h)</b>", section_heading))
        cccs_table_data = [[Paragraph("<b>Date</b>", cell_bold), Paragraph("<b>Advisory Title & Link</b>", cell_bold)]]
        for item in cccs_board[:6]:
            cccs_table_data.append([
                Paragraph(item['date'], cell_style),
                Paragraph(f"<b>{clean_html_tags(item['title'])}</b><br/><font color='#2B6CB0'><u><a href='{item['link']}'>Advisory Link</a></u></font>", cell_style)
            ])
        cccs_table = Table(cccs_table_data, colWidths=[65, 475])
        cccs_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#EDF2F7")),
            ('ALIGN', (0,0), (-1,-1), 'LEFT'),
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#CBD5E0")),
            ('TOPPADDING', (0,0), (-1,-1), 2),
            ('BOTTOMPADDING', (0,0), (-1,-1), 2),
        ]))
        story.append(cccs_table)
        story.append(Spacer(1, 6))

    if top_fyi_entries:
        story.append(Paragraph("<b>FYI Threat & Security Landscape (Past 24h Highlights)</b>", section_heading))
        fyi_table_data = [[Paragraph("<b>Date</b>", cell_bold), Paragraph("<b>Feed / Source</b>", cell_bold), Paragraph("<b>Headline & Impact Summary</b>", cell_bold)]]
        
        for entry in top_fyi_entries:
            headline_cell = f"<b>{clean_html_tags(entry['title'])}</b><br/>{clean_html_tags(entry['summary'])}<br/><font color='#2B6CB0'><u><a href='{entry['link']}'>Source Link</a></u></font>"
            fyi_table_data.append([
                Paragraph(entry['date'], cell_style),
                Paragraph(entry['feed'], cell_style),
                Paragraph(headline_cell, cell_style)
            ])
            
        fyi_table = Table(fyi_table_data, colWidths=[65, 110, 365])
        fyi_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#EDF2F7")),
            ('ALIGN', (0,0), (-1,-1), 'LEFT'),
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#CBD5E0")),
            ('TOPPADDING', (0,0), (-1,-1), 2),
            ('BOTTOMPADDING', (0,0), (-1,-1), 2),
        ]))
        story.append(fyi_table)
        story.append(Spacer(1, 6))
        story.append(Paragraph("<b>Actionable Threat Hunting Briefings & IOC Extraction (Past 24h)</b>", section_heading))

    if not reports:
        story.append(Paragraph("<b>No critical or high-severity threat briefings met the 24-hour threshold in this execution cycle.</b>", cell_style))
    
    for rep in reports:
        def format_bullets(text):
            cleaned = clean_html_tags(text)
            cleaned = cleaned.replace('\n• ', '<br/>• ').replace('\n-', '<br/>• ').replace('\n', '<br/>• ')
            if not cleaned.startswith('•') and not cleaned.startswith('<br/>'):
                cleaned = '• ' + cleaned
            return cleaned

        table_data = [
            [Paragraph(f"<b>[{rep['severity']}] {clean_html_tags(rep['title'])}</b>", cell_bold), Paragraph(f"<b>Date:</b> {clean_html_tags(rep['threat_date'])}", cell_style)],
            [Paragraph("<b>Source URL</b>", cell_bold), Paragraph(f"<font color='#2B6CB0'><u><a href='{rep['link']}'>{rep['link']}</a></u></font>", cell_style)],
            [Paragraph("<b>Executive Summary</b>", cell_bold), Paragraph(clean_html_tags(rep['exec_summary']), cell_style)],
            [Paragraph("<b>Threat Actor & Exploitation</b>", cell_bold), Paragraph(f"<b>Actor:</b> {clean_html_tags(rep['threat_group'])} | <b>Status:</b> {clean_html_tags(rep['exploitation_status'])}", cell_style)],
            [Paragraph("<b>Affected Tech / CVEs</b>", cell_bold), Paragraph(format_bullets(rep['affected_tech_cves']), cell_style)],
            [Paragraph("<b>Scope & Telemetry Impact</b>", cell_bold), Paragraph(format_bullets(rep['scope_impact']), cell_style)],
            [Paragraph("<b>MITRE ATT&CK TTPs</b>", cell_bold), Paragraph(format_bullets(rep['mitre_ttps']), cell_style)],
            [Paragraph("<b>Hunting Hypothesis</b>", cell_bold), Paragraph(format_bullets(rep['hunting_hypothesis']), cell_style)],
            [Paragraph("<b>Exploit Profile</b>", cell_bold), Paragraph(format_bullets(rep['successful_exploit_profile']), cell_style)],
            [Paragraph("<b>Sample Hunt Query</b>", cell_bold), Paragraph(clean_html_tags(rep['sample_hunt_query']), code_cell_style)],
        ]
        
        iocs = rep['iocs']
        ioc_summary_lines = []
        if iocs['ips']: ioc_summary_lines.append(f"<b>IPs ({len(iocs['ips'])}):</b> " + ", ".join(iocs['ips'][:10]))
        if iocs['domains']: ioc_summary_lines.append(f"<b>Domains ({len(iocs['domains'])}):</b> " + ", ".join(iocs['domains'][:15]))
        if iocs['sha256s']: ioc_summary_lines.append(f"<b>SHA256 ({len(iocs['sha256s'])}):</b> " + ", ".join([h[:12]+"..." for h in iocs['sha256s'][:10]]))
        if iocs['filenames']: ioc_summary_lines.append(f"<b>Files ({len(iocs['filenames'])}):</b> " + ", ".join(iocs['filenames'][:10]))
        if iocs['packages']: ioc_summary_lines.append(f"<b>Packages ({len(iocs['packages'])}):</b> " + ", ".join(iocs['packages'][:10]))
        
        if ioc_summary_lines:
            table_data.append([Paragraph("<b>Extracted IOCs</b>", cell_bold), Paragraph("<br/>".join(ioc_summary_lines), cell_style)])
            
        t = Table(table_data, colWidths=[130, 410])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#EDF2F7")),
            ('ALIGN', (0,0), (-1,-1), 'LEFT'),
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#CBD5E0")),
            ('TOPPADDING', (0,0), (-1,-1), 3),
            ('BOTTOMPADDING', (0,0), (-1,-1), 3),
        ]))
        
        story.append(t)
        story.append(Spacer(1, 6))

    # --- Last Page: Trending Global Outlook & Threat Telemetry ---
    story.append(PageBreak())
    story.append(Paragraph("<b>Trending Global Threat Outlook & Telemetry Dashboards</b>", title_style))
    story.append(Paragraph("<b>Executive Overview:</b> Global botnet C&C activity, infrastructure telemetry, and active internet outage corridors monitored via live threat telemetry feeds.", subtitle_style))
    story.append(HRFlowable(width="100%", thickness=1.2, color=colors.HexColor("#1A365D"), spaceAfter=10))

    story.append(Paragraph("<b>1. Active Botnet Command & Control (C&C) Infrastructure</b>", section_heading))
    story.append(Paragraph("Tracking active botnet C&C servers over time provides empirical baseline indicators of adversary infrastructure persistence and campaign pivots. Access live operational statistics directly below:", cell_style))
    story.append(Spacer(1, 4))
    story.append(Paragraph("<font color='#2B6CB0'><u><a href='https://feodotracker.abuse.ch/statistics/'>🔗 Feodo Tracker Active Botnet C&Cs Statistics & Live Charts</a></u></font>", cell_bold))
    story.append(Spacer(1, 10))

    story.append(Paragraph("<b>2. Global Internet Outages & Regional Disruptions (Cloudflare Radar)</b>", section_heading))
    story.append(Paragraph("Geopolitical conflicts, fiber cuts, and major infrastructure incidents generate measurable Autonomous System (AS) routing anomalies and traffic drops across financial corridors.", cell_style))
    story.append(Spacer(1, 4))
    story.append(Paragraph("<font color='#2B6CB0'><u><a href='https://radar.cloudflare.com/outage-center?dateRange=52w'>🔗 Cloudflare Radar 52-Week Global Outage Center</a></u></font><br/><font color='#2B6CB0'><u><a href='https://radar.cloudflare.com/?tab=outages&dateRange=7d'>🔗 Cloudflare Radar 7-Day Regional Outage & Traffic Map</a></u></font>", cell_bold))
    story.append(Spacer(1, 15))

    story.append(Paragraph("<b>Principal Threat Hunter Advisory Note:</b><br/>Integrate these global telemetry shifts into weekly hunting pivots. Correlate regional Cloudflare routing drops with inbound perimeter WAF telemetry to detect coordinated stealth probing during major infrastructure degradation events.", cell_style))

    doc.build(story)
    print(f"[*] Successfully generated executive PDF report with Global Outlook page: {PDF_FILENAME}")
except Exception as pdf_err:
    print(f"    [!] PDF generation error: {pdf_err}")

# --- 4. Construct and Send Clean Email with PDF Attachment Only ---
if os.path.exists(PDF_FILENAME):
    print(f"\n[*] Preparing final email digest...")
    msg = EmailMessage()
    msg['Subject'] = f"[Agentic Threat Intel Digest] Strategic Hunt & {len(reports)} Briefing(s)"
    msg['From'] = os.environ["GMAIL_USER"]
    msg['To'] = os.environ["GMAIL_RECIPIENT"]
    msg.set_content("Please find attached the latest Executive Threat Intelligence & Hunting Digest PDF containing prioritized threat briefings, extracted IOCs, sample hunting queries, CCCS/CSIS alerts, and the Global Threat Outlook telemetry page.")

    with open(PDF_FILENAME, "rb") as f:
        pdf_data = f.read()
    msg.add_attachment(
        pdf_data,
        maintype="application",
        subtype="pdf",
        filename=PDF_FILENAME
    )
    print("[*] Attached executive PDF report to email.")

    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
        smtp.login(os.environ["GMAIL_USER"], os.environ["GMAIL_APP_PASSWORD"])
        smtp.send_message(msg)
    print("[*] Executive Threat Intel Digest emailed successfully.")
else:
    print("\n[*] PDF report not found; email skipped.")