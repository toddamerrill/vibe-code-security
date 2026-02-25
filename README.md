# SSAP Security Study: "Insecure by Default"

**Full Title:** Insecure by Default: A Cross-Platform Security Analysis of 10,000 AI-Generated Web Applications

**Status:** Phase 1 — Discovery & Enumeration

## Project Structure

```
SSAP-Security-Study/
├── README.md                    # This file
├── METHODOLOGY.md               # Full research methodology
├── discovery/                   # App discovery & enumeration
│   ├── scrapers/                # Platform directory scrapers
│   │   ├── lovable_scraper.py   # launched.lovable.dev scraper
│   │   ├── bolt_scraper.py      # bolt.new/gallery + madewithbolt.com
│   │   ├── replit_scraper.py    # Replit community projects
│   │   ├── social_scraper.py    # Reddit/IndieHackers/ProductHunt mining
│   │   └── github_miner.py     # GitHub "built with [platform]" search
│   ├── ct-logs/                 # Certificate Transparency log mining
│   │   └── ct_log_miner.py     # crt.sh + Certstream enumeration
│   ├── fingerprinting/          # Vibe-code detection heuristics
│   │   └── vibe_fingerprint.py  # Score apps as vibe-coded or not
│   └── pipeline.py              # Master orchestration: discover → filter → curate
├── scanner/                     # SSAP vulnerability scanning
│   ├── scan_orchestrator.py     # Lambda-based parallel scanning
│   ├── header_scanner.py        # Security header checks
│   ├── secret_scanner.py        # JS bundle secret detection
│   ├── baas_prober.py           # Supabase/Firebase RLS deep probe
│   ├── auth_scanner.py          # Authentication security checks
│   ├── app_scanner.py           # DAST light (CORS, redirects, etc.)
│   └── grader.py                # A-F grade computation
├── analysis/                    # Statistical analysis
│   ├── analyze.py               # Main analysis script
│   ├── visualizations.py        # Chart generation
│   └── notebooks/               # Jupyter notebooks
├── article/                     # Scholarly article
│   ├── article.md               # Full article (Markdown)
│   └── figures/                 # Publication figures
├── marketing/                   # Companion content
│   ├── blog_post.md             # Developer-friendly blog version
│   ├── executive_summary.md     # 2-page summary for VCs/press
│   ├── infographic_spec.md      # Infographic design spec
│   └── social_content.md        # Twitter/LinkedIn posts
└── infra/                       # AWS infrastructure
    ├── cdk/                     # CDK stack for scanning infra
    └── lambda/                  # Lambda function packages
```

## Quick Start

```bash
# Phase 1: Discovery
cd discovery
pip install -r requirements.txt
python pipeline.py --phase discover    # Enumerate apps from all sources
python pipeline.py --phase fingerprint # Score and classify
python pipeline.py --phase curate      # Filter, dedupe, sample

# Phase 2: Scanning
cd ../scanner
python scan_orchestrator.py --input ../discovery/output/curated_apps.json

# Phase 3: Analysis
cd ../analysis
python analyze.py --input ../scanner/output/scan_results.json
```

## Timeline

| Phase | Weeks | Status |
|-------|-------|--------|
| Discovery & Enumeration | 1–3 | 🔄 In Progress |
| Scanning | 4–6 | ⬜ Pending |
| Analysis & Writing | 7–10 | ⬜ Pending |
| Publication & Marketing | 11–12 | ⬜ Pending |

## Key Contacts

- **Theron McLarty** — CISO review, technical validation
- **Todd Merrill** — Project lead, architecture
- **Kirby / CyberSavi** — MSP distribution of findings
