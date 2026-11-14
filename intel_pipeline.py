import os
import json
import smtplib
from email.message import EmailMessage
import feedparser
import trafilatura
import yfinance as yf
from google import genai
from google.genai import types
from pydantic import BaseModel, Field

# Configuration: Free OSINT RSS feeds
FEEDS = [
    "https://www.cisa.gov/cybersecurity-advisories/all.xml",
    "https://www.bleepingcomputer.com/feed/",
    "https://feeds.feedburner.com/TheHackersNews",
]
SEEN_FILE = "seen_urls.json"

# Load deduplication state
if os.path.exists(SEEN_FILE):
    with open(SEEN_FILE, "r") as f:
        seen_data = json.load(f)
else:
    seen_data = {"seen": []}

seen_urls = set(seen_data["seen"])

# Deterministic pre-filter keywords to save LLM tokens/rate limits
KEYWORDS = [
    "ransomware", "malware", "phishing", "vishing", "zero-day", "0-day",
    "supply chain", "cve-", "backdoor", "breach", "exploit", "npm", "pypi"
]

new_articles = []

for feed_url in FEEDS:
    parsed_feed = feedparser.parse(feed_url)
    for entry in parsed_feed.entries[:10]:
        link = getattr(entry, "link", "")
        title = getattr(entry, "title", "")
        pub_date = getattr(entry, "published", getattr(entry, "updated", "Unknown Date"))
        
        if not link or link in seen_urls:
            continue
        
        text_blob = f"{title} {getattr(entry, 'summary', '')}".lower()
        if any(kw in text_blob for kw in KEYWORDS):
            new_articles.append({
                "title": title,
                "link": link,
                "pub_date": pub_date
            })

if not new_articles:
    print("No new threat intel articles matching criteria.")
    exit(0)

# Initialize Gemini Client
client = genai.Client()

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
    affected_ticker: str = Field(description="Stock ticker symbol if a public company is impacted, otherwise 'N/A'")
    logscale_queries: list[str] = Field(description="LogScale queries tailored to the threat, following the user's exact syntax structures")
    splunk_queries: list[str] = Field(description="Splunk queries tailored to the threat, following the user's exact syntax structures")

reports = []

for article in new_articles:
    seen_urls.add(article["link"])
    
    downloaded = trafilatura.fetch_url(article["link"])
    article_text = trafilatura.extract(downloaded) if downloaded else article["title"]
    if not article_text:
        article_text = article["title"]

# Using standard string concatenation (+), avoiding all f-string and .format() brace conflicts
    prompt = """
    Analyze the following cyber security threat intelligence article for executive stakeholders and SOC threat hunters.
    Extract key IOCs or behavioral TTPs, and populate all executive briefing fields accurately.

    You must construct production-ready queries for CrowdStrike LogScale and Splunk modeled exactly after these user-provided templates:

    === LOGSCALE IOC TEMPLATE EXAMPLE ===
    case {
      in(RemoteAddressIP4, values=["203.0.113.45", "198.51.100.12"]) | ioc_match := "Malicious IP" | ioc_value := RemoteAddressIP4;
      in(DomainName, values=["example.com", "c2-server.net"]) | ioc_match := "Malicious Domain" | ioc_value := DomainName;
      in(SHA256HashData, values=["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"]) | ioc_match := "Malicious Hash" | ioc_value := SHA256HashData;
      * | dropEvent()
    }
    | table([@timestamp, ComputerName, ioc_match, ioc_value])

    === LOGSCALE BEHAVIORAL TEMPLATE EXAMPLE ===
    # event_simpleName=ProcessRollup2 
    (
      (CommandLine=~"tar " OR CommandLine=~"zip " OR CommandLine=~"gzip ") AND 
      (CommandLine=~".ssh" OR CommandLine=~".aws" OR CommandLine=~".azure")
    )
    | select([@timestamp, ComputerName, UserName, ImageFileName, CommandLine, ParentCommandLine])
    | sort([@timestamp], desc=true)

    === SPLUNK DATAMODEL TEMPLATE EXAMPLE ===
    | tstats count 
        from datamodel=Endpoint.Processes 
        where Processes.parent_process_name IN ("sshd", "sshd-session") 
              Processes.process_name IN ("sh", "ash", "bash", "dash") 
        by Processes.dest, Processes.user, Processes.parent_process_name, Processes.process_name, Processes.process, _time
    | rename Processes.* as *
    | sort - _time

    === SPLUNK INDEX FALLBACK TEMPLATE EXAMPLE ===
    index IN (*akamai*, *bluecoat*, *osnix*, *web*, *proxy*, *linux*, *pan*, *firewall*) (
        "103.216.220.92" OR "31.223.184.166" OR "0c5486f06620e26e316f4b33f318b0d646d5e1133789331aa2fed012360d1486"
    ) 
    | eval Matched_Category = case(
        like(_raw, "%php2shell%"), "Suspicious Scanner / Boundary Match",
        1=1, "Known Threat Actor IP / General IOC Match"
    )
    | fillnull value=-
    | table _time, index, host, src_ip, Matched_Category, _raw

    --- NOW PROCESS THIS ARTICLE ---
    Article Title: """ + article['title'] + """
    Feed Published Date: """ + article['pub_date'] + """
    URL: """ + article['link'] + """
    Content:
    """ + article_text[:4500]

    try:
        response = client.models.generate_content(
            model='gemini-3.8-flash',
            contents=prompt,
            config=types.GenerateContentConfig(
                response_mime_type="application/json",
                response_schema=ThreatAnalysis,
                thinking_level="low"
            ),
        )
        data = json.loads(response.text)
        
        stock_info = "N/A"
        ticker = data.get("affected_ticker", "N/A").strip().upper()
        if ticker and ticker != "N/A" and len(ticker) <= 5:
            try:
                stock = yf.Ticker(ticker)
                hist = stock.history(period="1d")
                if not hist.empty:
                    current_price = hist['Close'].iloc[-1]
                    stock_info = f"{ticker}: ${current_price:.2f} USD"
            except Exception:
                stock_info = f"{ticker}: Lookup failed"

        report_text = f"""
======================================================================
[{data.get('severity')}] THREAT INTEL BRIEFING: {article['title']}
======================================================================
• Threat Date        : {data.get('threat_date')} (Feed: {article['pub_date']})
• Executive Summary  : {data.get('exec_summary')}
• Campaign Status    : {data.get('is_new_campaign')}
• Threat Actor       : {data.get('threat_group')}
• Affected Tech/CVEs : {data.get('affected_tech_cves')}
• Exploitation State : {data.get('exploitation_status')}
• Scope & Impact     : {data.get('scope_impact')}
• Target Sectors     : {data.get('countries_industries')}
• MITRE ATT&CK       : {data.get('mitre_ttps')}
• Recommended Action : {data.get('recommended_action')}
• Affected Stock     : {stock_info}
• Source URL         : {article['link']}

--- LOGSCALE QUERIES ---
{'\n\n'.join(data.get('logscale_queries', []))}

--- SPLUNK QUERIES ---
{'\n\n'.join(data.get('splunk_queries', []))}
======================================================================
"""
        reports.append(report_text)
    except Exception as e:
        print(f"Error processing {article['link']}: {e}")

with open(SEEN_FILE, "w") as f:
    json.dump({"seen": list(seen_urls)[-1000:]}, f)

if reports:
    msg = EmailMessage()
    msg['Subject'] = f"[Threat Intel Digest] {len(reports)} New Briefing(s) - {new_articles[0]['pub_date'][:16]}"
    msg['From'] = os.environ["GMAIL_USER"]
    msg['To'] = os.environ["GMAIL_RECIPIENT"]
    msg.set_content("\n".join(reports))

    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
        smtp.login(os.environ["GMAIL_USER"], os.environ["GMAIL_APP_PASSWORD"])
        smtp.send_message(msg)
    print("Threat intel digest emailed successfully.")