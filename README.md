# TraceLab — Digital Crime Scene Reconstructor

A beginner-friendly Streamlit cybersecurity project for educational phishing triage and digital incident reporting.

## Features
- URL heuristic checks (does not fetch or open URLs)
- Suspicious wording indicators for pasted messages
- Case score and triage level
- Generated investigation workflow timeline
- Evidence relationship view
- Downloadable JSON and TXT reports
- Session dashboard and CSV export

## Run locally
Requires Python 3.9+.

```bash
pip install -r requirements.txt
streamlit run app.py
```

## Deploy on Streamlit Community Cloud
1. Upload `app.py`, `requirements.txt`, and `README.md` to a GitHub repository.
2. On Streamlit Community Cloud, create an app from that repository.
3. Set the main file path to `app.py`.

## Safety and limitations
This is educational, rule-based triage, not a definitive detector or a forensic tool. Scores are not probabilities. Low risk does not mean safe. The app does not visit URLs or prove an attack occurred. Session history is temporary and is not stored in a database. Use fictional or sanitized test data and do not enter passwords or private tokens.
