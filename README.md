# Email Header Analyzer — Desktop

A standalone, offline desktop tool for inspecting the headers and content of email messages (`.eml` files). Built for SOC analysts, incident responders, and security awareness teams who need a quick, trustworthy read on **where a message came from, what it claims, and what it carries** — without sending any data to a third party.

Everything runs locally. No network calls, no telemetry, no cloud lookup.

---

## Features

- **Authentication verdicts** — SPF, DKIM, DMARC results and full `Authentication-Results` declarations, including policy and client-IP details.
- **Mail-flow reconstruction** — parses the `Received:` chain into a crawl: source IP, source host/HELO, hop count, intermediate MTAs, destination, and a confidence rating.
- **Sender identity checks** — compares `From` / `Sender` / `Reply-To` / `Return-Path`, flags obfuscated display names and missing mailer headers.
- **Attachments** — lists every MIME attachment with name, type, size, and disposition, and offers a **Save as…** action that writes the decoded payload to disk (original bytes preserved via base64 decoding).
- **URL extraction** — finds and de-duplicates URLs in the decoded plain-text and HTML body, with one-click copy.
- **Passive indicators** — a severity-ranked list of observations (never a "malicious/good" verdict) that helps you judge a message on its facts.
- **Raw headers + export** — full raw header view, plus JSON and plain-text report export.

### Interface

Tabs: **Authentication** · **Sender** · **Attachments & URLs** · **Mail Flow** · **Indicators** · **Raw Headers**

The header bar shows at-a-glance chips for SPF / DKIM / DMARC / source IP and a source-confidence banner.

---

## Requirements

- **Python 3.9 or newer**
- Standard library only — there are **no third-party dependencies** (`requirements.txt` is a formality documenting this).

Tkinter ships with the official CPython installer on Windows/macOS; on Linux install e.g. `python3-tk` if missing.

---

## Quick start

```bash
# Clone or copy the project, then:
python main.py                        # open the GUI
python main.py path\to\message.eml    # open a message immediately
```

Or double-click `run.bat` on Windows.

**Headless smoke check** (used in CI / as a sanity test):

```bash
python main.py --headless
```

---

## Usage walkthrough

1. Launch the app and click **Open .eml…** (or drag a file onto the window / press `Ctrl+O`).
2. Review the greeting chips: SPF / DKIM / DMARC / source IP.
3. Explore the tabs:
   - **Authentication** — verdicts, domains, policies, alignment, and raw declarations.
   - **Sender** — all identity addresses and any differences between them.
   - **Attachments & URLs** — inspect and save attachments; copy suspicious URLs.
   - **Mail Flow** — the reconstructed hop-by-hop trail.
   - **Indicators** — ranked observations with severity.
   - **Raw Headers** — the untouched header block.
4. Export the full report via **Export JSON** or **Export Text** if you want it in a ticket or SIEM.

---

## Testing

```bash
python -m unittest discover -s tests -v
```

Or `run_tests.bat` on Windows.

The suite covers SPF/DKIM/DMARC parsing, routing reconstruction, identity checks, MIME/attachment/URL extraction, and end-to-end analysis of real fixture files (`full.eml`, `ipv6.eml`, `spoofy.eml`).

---

## Project structure

```
EmailHeaderAnalyzer-Desktop/
├── main.py                 # Entry point
├── gui.py                  # Tkinter interface (tabs, exports, save-attachment)
├── email_analysis.py       # Pure analysis logic — no GUI dependencies
├── requirements.txt        # Documents that the app is stdlib-only
├── run.bat / run_tests.bat # Windows launchers
├── README.md
└── tests/
    ├── test_email_analysis.py
    └── fixtures/*.eml
```

### Architecture

`main.py` → `gui.py` → `email_analysis.py`. The analysis layer is a pure-Python port of the browser-extension pipeline (`parser/` + `analyzer/` in the sibling extension project) and is fully testable without a GUI.

---

## Security & privacy notes

- **Fully offline.** The app never contacts the network; DKIM/SPF/DMARC results are reported exactly as the receiving provider recorded them in `Authentication-Results`.
- **No verdicts.** The tool reports passive facts and indicators only — it never labels a message as malicious. Correlation, context, and judgement are left to you.
- **Attachments are handled locally.** "Save as…" writes the decoded bytes from the message file to the path you choose; nothing is uploaded or executed.

---

## Limitations

- Authentication verdicts are as recorded by the receiving provider (e.g. Gmail's `Authentication-Results`); the app does not perform DNS lookups.
- Confidence for single-hop messages (e.g. webmail) reflects the provider's MTA, not the end-user device.
- URL extraction is heuristic (bare-URL + HTML-attribute regex) and may include benign or malformed strings.

---

## License

Proprietary / internal use. See your organization's policy for distribution.