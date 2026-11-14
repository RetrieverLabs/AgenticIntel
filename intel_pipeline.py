import os
import json
import time
import random
import smtplib
from email.message import EmailMessage
import feedparser
import requests
import trafilatura
from groq import Groq
from pydantic import BaseModel, Field

# Configuration: Free OSINT RSS feeds
FEEDS = [
    "https://www.cisa.gov/cybersecurity-advisories/all.xml",
    "https://www.bleepingcomputer.com/feed/",
    "https://feeds.feedburner.com/TheHackersNews",
]
SEEN_FILE = "seen_urls.json"

# Realistic browser user-agents to bypass anti-bot scrapers
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36"
]

# Load deduplication state
if os.path.exists(SEEN_FILE):
    with open(SEEN_FILE, "r") as f:
        seen_data = json.load(f)
else:
    seen_data = {"seen": []}

seen_urls = set(seen_data["seen"])

# Stricter pre-filter keywords focused on critical severity and severe exploitation
KEYWORDS = [
    "critical", "cvss 9", "cvss 10", "rce", "remote code execution",
    "zero-day", "0-day", "actively exploited", "ransomware", "supply chain"
]

new_articles = []

print("[*] Starting RSS feed parsing and keyword pre-filtering...")
for feed_url in FEEDS:
    print(f"[*] Parsing feed: {feed_url}")
    parsed_feed = feedparser.parse(feed_url)
    print(f"    -> Found {len(parsed_feed.entries)} total entries in feed.")
    
    # Sliced to top 3 for speed and noise reduction
    for entry in parsed_feed.entries[:3]:
        link = getattr(entry, "link", "")
        title = getattr(entry, "title", "")
        pub_date = getattr(entry, "published", getattr(entry, "updated", "Unknown Date"))
        
        if not link or link in seen_urls:
            continue
        
        text_blob = f"{title} {getattr(entry, 'summary', '')}".lower()
        if any(kw in text_blob for kw in KEYWORDS):
            print(f"    [+] Match found: {title[:60]}...")
            new_articles.append({
                "title": title,
                "link": link,
                "pub_date": pub_date
            })

print(f"\n[*] Total new unique articles matching critical criteria: {len(new_articles)}")

if not new_articles:
    print("No new high-severity threat intel articles matching criteria. Exiting.")
    exit(0)

# Initialize Groq Client
client = Groq(api_key=os.environ.get("GROQ_API_KEY"))

class ThreatAnalysis(BaseModel):
    threat_date: str = Field(description="Date the threat/campaign was reported or first observed (YYYY-MM-DD format if possible)")
    severity: str = Field(description="Urgency rating: CRITICAL, HIGH, MEDIUM, or LOW")
    exec_summary: str = Field(description="One-liner executive summary of the threat")
    is_new_campaign: str = Field(description="'New' or 'Seen Before / Variant'")
    threat_group: str = Field(description="Attribution/Threat actor if known, else 'Unknown'")
    affected_tech_cves: str = Field(description="Impacted software, appliances, packages, and CVE IDs (or 'N/A')")
    exploitation_status: str = Field(description="e.g., 'Actively Exploited in the Wild', 'PoC Public', 'Theoretical / Patched', or 'Unknown'")
    scope_impact: str = Field(description="Brief scope and potential business/operational impact")
    countries_industries: str = Field(description="Impacted countries and industries")
    mitre_ttps: str = Field(description="Key MITRE ATT&CK IDs and names")
    recommended_action: str = Field(description="Concrete 1-sentence remediation or defensive action for stakeholders")
    logscale_queries: list[str] = Field(description="LogScale queries tailored to the threat, following the user's exact syntax structures")
    splunk_queries: list[str] = Field(description="Splunk queries tailored to the threat, following the user's exact syntax structures")

reports = []

for i, article in enumerate(new_articles, 1):
    seen_urls.add(article["link"])
    print(f"\n[*] Processing [{i}/{len(new_articles)}]: {article['title']}")
    
    # Human-like browser headers & anti-bot evasion
    headers = {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "DNT": "1",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1"
    }
    
    try:
        response = requests.get(article["link"], headers=headers, timeout=10)
        downloaded = response.text if response.status_code == 200 else None
    except Exception as e:
        print(f"    [!] Request warning for {article['link']}: {e}")
        downloaded = None

    article_text = trafilatura.extract(downloaded) if downloaded else article["title"]
    if not article_text:
        article_text = article["title"]

    logscale_ioc_template = (
        "case {\n"
        "  in(RemoteAddressIP4, values=[\"203.0.113.45\", \"198.51.100.12\"]) | ioc_match := \"Malicious IP\" | ioc_value := RemoteAddressIP4;\n"
        "  in(DomainName, values=[\"example.com\", \"c2-server.net\"]) | ioc_match := \"Malicious Domain\" | ioc_value := DomainName;\n"
        "  in(SHA256HashData, values=[\"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\"]) | ioc_match := \"Malicious Hash\" | ioc_value := SHA256HashData;\n"
        "  * | dropEvent()\n"
        "}\n"
        "| table([@timestamp, ComputerName, ioc_match, ioc_value])"
    )

    logscale_beh_template = (
        "# event_simpleName=ProcessRollup2 \n"
        "(\n"
        "  (CommandLine=~\"tar \" OR CommandLine=~\"zip \" OR CommandLine=~\"gzip \") AND \n"
        "  (CommandLine=~\".ssh\" OR CommandLine=~\".aws\" OR CommandLine=~\".azure\")\n"
        ")\n"
        "| select([@timestamp, ComputerName, UserName, ImageFileName, CommandLine, ParentCommandLine])\n"
        "| sort([@timestamp], desc=true)"
    )

    splunk_dm_template = (
        "| tstats count \n"
        "    from datamodel=Endpoint.Processes \n"
        "    where Processes.parent_process_name IN (\"sshd\", \"sshd-session\") \n"
        "          Processes.process_name IN (\"sh\", \"ash\", \"bash\", \"dash\") \n"
        "    by Processes.dest, Processes.user, Processes.parent_process_name, Processes.process_name, Processes.process, _time\n"
        "| rename Processes.* as *\n"
        "| sort - _time"
    )

    splunk_fallback_template = (
        "index IN (*akamai*, *bluecoat*, *osnix*, *web*, *proxy*, *linux*, *pan*, *firewall*) (\n"
        "    \"103.216.220.92\" OR \"31.223.184.166\" OR \"0c5486f06620e26e316f4b33f318b0d646d5e1133789331aa2fed012360d1486\"\n"
        ") \n"
        "| rex field=_raw \"(?i)(?:client[_-]?ip|src[_-]?ip|src)[=:\\s]+(?<src_ip>\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})\"\n"
        "| eval Matched_Category = case(\n"
        "    like(_raw, \"%php2shell%\"), \"Suspicious Scanner / Boundary Match\",\n"
        "    1=1, \"Known Threat Actor IP / General IOC Match\"\n"
        ")\n"
        "| fillnull value=-\n"
        "| table _time, index, host, src_ip, Matched_Category, _raw"
    )

    system_prompt = (
        "You are an expert cyber security threat intelligence analyst and threat hunter. "
        "Analyze the provided article and return valid JSON matching the required schema. "
        "Ensure production-ready SIEM queries are written in LogScale and Splunk using exact syntax rules."
    )

    user_prompt = (
        "Analyze the following cyber security threat intelligence article for executive stakeholders and SOC threat hunters.\n"
        "Extract key IOCs or behavioral TTPs, and populate all executive briefing fields accurately.\n\n"
        "You must construct production-ready queries for CrowdStrike LogScale and Splunk modeled exactly after these templates:\n\n"
        "=== LOGSCALE IOC TEMPLATE ===\n" + logscale_ioc_template + "\n\n"
        "=== LOGSCALE BEHAVIORAL TEMPLATE ===\n" + logscale_beh_template + "\n\n"
        "=== SPLUNK DATAMODEL TEMPLATE ===\n" + splunk_dm_template + "\n\n"
        "=== SPLUNK FALLBACK TEMPLATE ===\n" + splunk_fallback_template + "\n\n"
        "--- NOW PROCESS THIS ARTICLE ---\n"
        "Article Title: " + article['title'] + "\n"
        "Feed Published Date: " + article['pub_date'] + "\n"
        "URL: " + article['link'] + "\n"
        "Content:\n" + article_text[:4500]
    )

    try:
        print(f"    -> Querying Groq (llama-3.3-70b-versatile)...")

        # Exponential Backoff Retry Loop for Groq
        response_obj = None
        for attempt in range(4):
            try:
                response_obj = client.chat.completions.create(
                    model="llama-3.3-70b-versatile",
                    messages=[
                        {"role": "system", "content": system_prompt + f"\n\nReturn ONLY valid JSON matching this schema: {ThreatAnalysis.model_json_schema()}"},
                        {"role": "user", "content": user_prompt}
                    ],
                    response_format={"type": "json_object"},
                    temperature=0.1
                )
                break
            except Exception as api_err:
                err_str = str(api_err)
                if "429" in err_str or "503" in err_str or "Rate limit" in err_str:
                    if attempt == 3:
                        raise api_err
                    wait_time = 5 * (2 ** attempt)
                    print(f"    [!] Rate limited or busy. Retrying in {wait_time}s...")
                    time.sleep(wait_time)
                else:
                    raise api_err

        raw_content = response_obj.choices[0].message.content
        data = json.loads(raw_content)
        severity = data.get('severity', '').strip().upper()
        print(f"    -> Analysis generated successfully. Severity: {severity}")

        # Gatekeeper: Discard anything below HIGH or CRITICAL to eliminate noise
        if severity not in ["CRITICAL", "HIGH"]:
            print(f"    -> Skipping briefing: Severity '{severity}' is below threshold (High/Critical only).")
            continue

        logscale_joined = "\n\n".join(data.get('logscale_queries', []))
        splunk_joined = "\n\n".join(data.get('splunk_queries', []))

        report_text = (
            "======================================================================\n" +
            "[" + severity + "] THREAT INTEL BRIEFING: " + str(article.get('title', '')) + "\n" +
            "======================================================================\n" +
            "• Threat Date        : " + str(data.get('threat_date', '')) + " (Feed: " + str(article.get('pub_date', '')) + ")\n" +
            "• Executive Summary  : " + str(data.get('exec_summary', '')) + "\n" +
            "• Campaign Status    : " + str(data.get('is_new_campaign', '')) + "\n" +
            "• Threat Actor       : " + str(data.get('threat_group', '')) + "\n" +
            "• Affected Tech/CVEs : " + str(data.get('affected_tech_cves', '')) + "\n" +
            "• Exploitation State : " + str(data.get('exploitation_status', '')) + "\n" +
            "• Scope & Impact     : " + str(data.get('scope_impact', '')) + "\n" +
            "• Target Sectors     : " + str(data.get('countries_industries', '')) + "\n" +
            "• MITRE ATT&CK       : " + str(data.get('mitre_ttps', '')) + "\n" +
            "• Recommended Action : " + str(data.get('recommended_action', '')) + "\n" +
            "• Source URL         : " + str(article.get('link', '')) + "\n\n" +
            "--- LOGSCALE QUERIES ---\n" +
            logscale_joined + "\n\n" +
            "--- SPLUNK QUERIES ---\n" +
            splunk_joined + "\n" +
            "======================================================================"
        )
        reports.append(report_text)
        print(f"    -> Added high-priority report to digest queue.")
        
    except Exception as e:
        print(f"    [!] Error processing {article['link']}: {e}")

    # Brief pacing pause (Groq handles high throughput well, but a 2s pause is good hygiene)
    time.sleep(2.0)

with open(SEEN_FILE, "w") as f:
    json.dump({"seen": list(seen_urls)[-1000:]}, f)

if reports:
    print(f"\n[*] Preparing email digest containing {len(reports)} high-severity report(s)...")
    msg = EmailMessage()
    msg['Subject'] = f"[Threat Intel Digest] {len(reports)} High/Critical Briefing(s) - {new_articles[0]['pub_date'][:16]}"
    msg['From'] = os.environ["GMAIL_USER"]
    msg['To'] = os.environ["GMAIL_RECIPIENT"]
    msg.set_content("\n".join(reports))

    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
        smtp.login(os.environ["GMAIL_USER"], os.environ["GMAIL_APP_PASSWORD"])
        smtp.send_message(msg)
    print("[*] Threat intel digest emailed successfully.")
else:
    print("\n[*] No High/Critical reports generated. Skipping email.")