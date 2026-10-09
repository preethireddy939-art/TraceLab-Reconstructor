import streamlit as st
import re, json, csv, io
from urllib.parse import urlparse
from datetime import datetime

st.set_page_config(page_title="TraceLab | Digital Crime Scene Reconstructor", page_icon="🕵️", layout="wide")

# Educational, local-only heuristic triage. Submitted URLs are never fetched or opened.
SUSPICIOUS_WORDS = ["verify", "urgent", "password", "login", "account suspended", "payment", "invoice", "gift card", "confirm", "security alert", "limited time", "reset", "bank"]
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "shorturl.at", "rb.gy", "ow.ly"}

if "cases" not in st.session_state:
    st.session_state.cases = []


def clean_url(raw):
    value = (raw or "").strip()
    if not value:
        return ""
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", value):
        value = "https://" + value
    return value


def analyze_url(raw):
    findings = []
    url = clean_url(raw)
    if not url:
        return {"url": "", "score": 0, "level": "Not assessed", "findings": [], "host": ""}
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    if not host:
        findings.append((18, "URL could not be parsed", "The text does not look like a normal web address."))
    if parsed.scheme != "https":
        findings.append((8, "No HTTPS scheme", "The address does not specify HTTPS. This alone does not prove maliciousness."))
    if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", host):
        findings.append((18, "IP address used as host", "The host is an IPv4 address rather than a domain name."))
    if host in SHORTENERS:
        findings.append((12, "Link-shortening domain", "The destination is obscured by a known URL shortener."))
    if "xn--" in host:
        findings.append((16, "Punycode in domain", "The domain contains an internationalized-domain encoding that deserves review."))
    if host.count(".") >= 4:
        findings.append((10, "Many subdomain levels", "The host contains several subdomain levels; inspect the registered domain carefully."))
    if "@" in url:
        findings.append((15, "At-sign in URL", "An at-sign can make the apparent destination confusing."))
    if len(url) > 120:
        findings.append((8, "Unusually long URL", "Long addresses can hide confusing paths or parameters."))
    if re.search(r"%[0-9a-fA-F]{2}", url):
        findings.append((5, "Percent-encoded characters", "The URL contains encoded characters; this is common but can reduce readability."))
    if host and any(token in host for token in ["secure-login", "account-verify", "password-reset", "signin-check"]):
        findings.append((18, "Login/verification wording in host", "The hostname includes language often used in account-lure links."))
    score = min(100, sum(item[0] for item in findings))
    level = "High" if score >= 45 else "Medium" if score >= 20 else "Low"
    return {"url": url, "score": score, "level": level, "findings": [{"points": p, "indicator": title, "explanation": why} for p, title, why in findings], "host": host}


def analyze_message(message):
    text = (message or "").lower()
    matches = [word for word in SUSPICIOUS_WORDS if word in text]
    return matches


def build_case(case_id, analyst, incident_type, url_text, message, notes):
    url_result = analyze_url(url_text)
    message_hits = analyze_message(message)
    extra_points = min(30, len(message_hits) * 5)
    combined = min(100, url_result["score"] + extra_points)
    level = "High" if combined >= 45 else "Medium" if combined >= 20 else "Low"
    now = datetime.now().astimezone().isoformat(timespec="seconds")
    events = []
    events.append({"stage": "Report received", "status": "Provided by investigator", "detail": "Incident details entered into TraceLab."})
    if message:
        events.append({"stage": "Message reviewed", "status": "Text indicators checked", "detail": f"{len(message_hits)} suspicious wording pattern(s) matched."})
    if url_text:
        events.append({"stage": "URL triaged", "status": "Local heuristic checks", "detail": f"{len(url_result['findings'])} URL indicator(s) found for host {url_result['host'] or 'unparsed address'}."})
    events.append({"stage": "Analyst review", "status": "Recommended next step", "detail": "Verify sender and destination through an independent trusted channel; preserve original evidence."})
    return {"case_id": case_id, "created_at": now, "analyst": analyst or "Not specified", "incident_type": incident_type, "url": url_result, "message_indicators": message_hits, "combined_score": combined, "risk_level": level, "notes": notes, "timeline": events,
            "limitations": ["This is educational heuristic triage, not a definitive verdict.", "No submitted URL was visited, fetched, or opened by this app.", "Timeline stages are generated from supplied information and are not proof that an attack occurred."]}

st.markdown("""<style>
.block-container{padding-top:1.5rem;max-width:1200px}
.hero{padding:1.35rem 1.5rem;border-radius:18px;background:linear-gradient(120deg,#102735,#153e4a);color:#f4fbff;border:1px solid #2b5a64;margin-bottom:1rem}
.hero h1{margin:0 0 .25rem 0;font-size:2rem}.hero p{margin:0;color:#c6e3e8}
.pill{display:inline-block;padding:.2rem .6rem;border-radius:20px;border:1px solid #6a929b;font-size:.78rem;margin-right:.35rem}
.evidence{border:1px solid rgba(128,128,128,.28);border-radius:12px;padding:12px;margin:8px 0}
.small-muted{font-size:.86rem;opacity:.78}
</style>""", unsafe_allow_html=True)
st.markdown('<div class="hero"><div class="pill">CYBER FORENSICS • EDUCATIONAL</div><h1>🕵️ TraceLab</h1><p>Digital Crime Scene Reconstructor — connect evidence, inspect indicators, and create a defensible incident report.</p></div>', unsafe_allow_html=True)
st.warning("Safety boundary: TraceLab never opens or visits submitted URLs. Its risk score is a heuristic signal, not proof that a site is malicious or safe.")

with st.sidebar:
    st.header("Investigation workspace")
    st.write("Use fictional or sanitized examples. Do not paste passwords, private tokens, or sensitive personal data.")
    st.divider()
    st.metric("Cases this session", len(st.session_state.cases))
    if st.button("Clear session history", use_container_width=True):
        st.session_state.cases = []
        st.rerun()
    st.caption("History stays only in this browser session and is not saved to a database.")

page = st.radio("Workspace", ["New investigation", "Case dashboard", "How it works"], horizontal=True, label_visibility="collapsed")

if page == "New investigation":
    left, right = st.columns([1.05, .95], gap="large")
    with left:
        st.subheader("1 · Record the incident")
        with st.form("case_form"):
            analyst = st.text_input("Analyst / student name (optional)", placeholder="e.g., Student Investigator")
            incident_type = st.selectbox("Incident category", ["Suspected phishing", "Suspicious message", "Account impersonation", "Payment scam", "Unknown / other"])
            url_text = st.text_input("Suspicious URL (optional)", placeholder="example.com/login")
            message = st.text_area("Message or incident text (optional)", height=150, placeholder="Paste a sanitized suspicious message here…")
            notes = st.text_area("Investigator notes", height=90, placeholder="Where was it reported? What has been verified? What is still unknown?")
            submitted = st.form_submit_button("Reconstruct digital crime scene", type="primary", use_container_width=True)
        if submitted:
            case_id = "TL-" + datetime.now().strftime("%y%m%d-%H%M%S")
            case = build_case(case_id, analyst, incident_type, url_text, message, notes)
            if not url_text.strip() and not message.strip() and not notes.strip():
                st.error("Add at least a URL, message text, or investigator note before creating a case.")
            else:
                st.session_state.cases.insert(0, case)
                st.session_state.latest_case = case
                st.success(f"Investigation created: {case_id}")
    with right:
        st.subheader("2 · Evidence principles")
        st.markdown("""<div class="evidence"><b>🔎 Observe</b><br><span class="small-muted">Record what was actually supplied: URL, wording, source, and context.</span></div><div class="evidence"><b>🧩 Correlate</b><br><span class="small-muted">Link indicators to the exact evidence that triggered them.</span></div><div class="evidence"><b>⏱ Reconstruct</b><br><span class="small-muted">Create a cautious sequence of investigation stages, not invented facts.</span></div><div class="evidence"><b>🛡 Recommend</b><br><span class="small-muted">Preserve evidence and verify through a separate trusted channel.</span></div>""", unsafe_allow_html=True)
        st.info("Tip: a real investigation distinguishes observed evidence, automated indicators, and hypotheses.")

    case = st.session_state.get("latest_case")
    if case:
        st.divider()
        st.subheader("3 · Reconstructed case")
        a, b, c = st.columns(3)
        a.metric("Case ID", case["case_id"])
        b.metric("Combined heuristic score", f"{case['combined_score']}/100")
        c.metric("Triage level", case["risk_level"])
        st.caption(f"Created: {case['created_at']} · Category: {case['incident_type']}")
        tab1, tab2, tab3, tab4 = st.tabs(["Evidence findings", "Attack timeline", "Relationship map", "Export report"])
        with tab1:
            st.markdown("**URL indicators**")
            if case["url"]["url"]:
                st.code(case["url"]["url"], language=None)
                if case["url"]["findings"]:
                    for item in case["url"]["findings"]:
                        st.markdown(f"<div class='evidence'><b>+{item['points']} · {item['indicator']}</b><br><span class='small-muted'>{item['explanation']}</span></div>", unsafe_allow_html=True)
                else:
                    st.success("No configured URL warning indicators matched. This does not establish safety.")
            else:
                st.write("No URL supplied.")
            st.markdown("**Message wording indicators**")
            if case["message_indicators"]:
                st.write(", ".join(f"`{x}`" for x in case["message_indicators"]))
            else:
                st.write("No configured wording patterns matched, or no message was supplied.")
            if case["notes"]:
                st.markdown("**Investigator notes**")
                st.write(case["notes"])
        with tab2:
            st.markdown("**Investigation sequence**")
            for i, event in enumerate(case["timeline"], 1):
                st.markdown(f"<div class='evidence'><b>{i}. {event['stage']}</b> · {event['status']}<br><span class='small-muted'>{event['detail']}</span></div>", unsafe_allow_html=True)
            st.caption("This is a workflow timeline generated from entered information, not a verified timeline of attacker actions.")
        with tab3:
            st.markdown("**Evidence relationship map**")
            nodes = [("Incident report", "#183e4a")]
            if case["message_indicators"]: nodes.append(("Message wording", "#805b27"))
            if case["url"]["url"]: nodes.append(("Submitted URL", "#315e8b"))
            nodes.append(("Triage assessment", "#3d684b"))
            cols = st.columns(len(nodes))
            for idx, (label, color) in enumerate(nodes):
                with cols[idx]:
                    st.markdown(f"<div style='min-height:88px;display:flex;align-items:center;justify-content:center;text-align:center;padding:10px;border-radius:12px;background:{color};color:white;font-weight:600'>{label}</div>", unsafe_allow_html=True)
                if idx < len(nodes)-1:
                    pass
            st.caption("Relationship shown: supplied incident information → checked evidence → heuristic triage. Connections do not establish causation.")
        with tab4:
            report = json.dumps(case, indent=2, ensure_ascii=False)
            st.download_button("Download full JSON case file", report, file_name=f"{case['case_id']}.json", mime="application/json", use_container_width=True)
            lines = [f"TRACELAB DIGITAL INCIDENT REPORT", f"Case ID: {case['case_id']}", f"Created: {case['created_at']}", f"Analyst: {case['analyst']}", f"Category: {case['incident_type']}", f"Heuristic score: {case['combined_score']}/100", f"Triage level: {case['risk_level']}", "", "URL findings:"]
            lines += [f"- {x['indicator']} (+{x['points']}): {x['explanation']}" for x in case['url']['findings']] or ["- No configured URL indicators matched / no URL supplied."]
            lines += ["", "Message indicators: " + (", ".join(case['message_indicators']) or "None matched / no message supplied"), "", "Investigator notes:", case['notes'] or "None", "", "Timeline:"]
            lines += [f"- {x['stage']}: {x['detail']}" for x in case['timeline']]
            lines += ["", "Limitations:"] + ["- " + x for x in case['limitations']]
            st.download_button("Download readable TXT report", "\n".join(lines), file_name=f"{case['case_id']}_report.txt", mime="text/plain", use_container_width=True)

elif page == "Case dashboard":
    st.subheader("Investigation dashboard")
    cases = st.session_state.cases
    if not cases:
        st.info("No cases in this session yet. Create a new investigation first.")
    else:
        c1, c2, c3 = st.columns(3)
        c1.metric("Total cases", len(cases))
        c2.metric("High triage", sum(x["risk_level"] == "High" for x in cases))
        c3.metric("URLs reviewed", sum(bool(x["url"]["url"]) for x in cases))
        for case in cases:
            with st.expander(f"{case['case_id']} · {case['incident_type']} · {case['risk_level']} ({case['combined_score']}/100)"):
                st.write(f"Created: {case['created_at']} · Analyst: {case['analyst']}")
                st.write("URL host:", case["url"]["host"] or "Not provided")
                st.download_button("Download this case JSON", json.dumps(case, indent=2), file_name=f"{case['case_id']}.json", mime="application/json", key="dl_"+case["case_id"])
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["case_id", "created_at", "analyst", "incident_type", "url", "url_score", "combined_score", "risk_level", "message_indicators", "notes"])
        for x in cases:
            writer.writerow([x["case_id"], x["created_at"], x["analyst"], x["incident_type"], x["url"]["url"], x["url"]["score"], x["combined_score"], x["risk_level"], "; ".join(x["message_indicators"]), x["notes"]])
        st.download_button("Export session dashboard as CSV", output.getvalue(), file_name="tracelab_cases.csv", mime="text/csv")
        st.caption("Session history is temporary. Download reports before closing or refreshing the session.")

else:
    st.subheader("How TraceLab works")
    st.markdown("""1. **Input:** investigator supplies a URL, sanitized message, and optional notes.
2. **Local checks:** the app looks for configured URL patterns and suspicious wording. It does not perform network requests.
3. **Evidence correlation:** findings remain attached to their source type so the investigator can explain the score.
4. **Reconstruction:** the app generates a workflow timeline and a simple relationship view.
5. **Reporting:** export a JSON evidence record, readable TXT report, or session CSV.

**Limitations:** The rules can produce false positives and false negatives. A low score is not a safety guarantee. The app does not verify ownership, inspect page contents, trace a real attacker, or establish that an attack happened. Use it as an educational triage aid, not as forensic proof.""")
    st.subheader("Suggested demonstration")
    st.write("Use a fictional sample like `http://192.0.2.10/secure-login?verify=1` and a mock message such as `Urgent: verify your account password now`. The IP address range 192.0.2.0/24 is reserved for documentation examples.")
    st.code("http://192.0.2.10/secure-login?verify=1\nUrgent: verify your account password now", language=None)

st.divider()
st.caption("TraceLab • Student cybersecurity project • Privacy-first local heuristic analysis • No URLs are visited")
