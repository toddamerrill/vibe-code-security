# Insecure by Default: A Cross-Platform Security Analysis of AI-Generated Web Applications

**Authors:** Kirby Winters & Todd Merrill
**Published:** February 2026
**Status:** ✅ Complete

---

## 🔒 Scan Your Vibe-Coded App for Free

**Built with Cursor, Bolt, Lovable, v0, or Replit?** Find out if your app has the same vulnerabilities we discovered in this study.

👉 **[Get Your Free Security Scan](https://securestackscan.com)** — 60 seconds, no credit card required.

---

## Key Findings

We analyzed **603 production AI-built web applications** across Lovable, Bolt, and Replit. The results reveal systematic security gaps in vibe-coded applications:

| Metric | Finding |
|--------|---------|
| **Average Security Score** | 75.3 / 100 (C grade) |
| **Apps Achieving A Grade** | 0% |
| **Apps Receiving C Grade** | 91.7% |
| **Missing Content-Security-Policy** | 98.5% |
| **Missing X-Frame-Options** | 98.5% |
| **Missing HSTS** | 87.2% |
| **Exposed Source Maps** | 34.1% |

### The Bottom Line

AI coding tools produce functional applications but systematically skip defense-in-depth security controls. The apps aren't catastrophically broken—they're just **insecure by default**.

---

## Abstract

The rise of AI-assisted coding tools—Cursor, GitHub Copilot, Claude Code, Bolt, v0, Lovable, and Replit—has democratized software development. Non-technical founders can now ship production applications in hours. But what is the security posture of these "vibe-coded" applications?

This study presents the largest empirical security analysis of AI-generated web applications to date. We enumerated 603 production applications built on Lovable, Bolt, and Replit, then scanned each for common vulnerabilities: missing security headers, exposed secrets, insecure BaaS configurations, and OWASP Top 10 risks.

Our findings reveal a consistent pattern: AI coding tools optimize for functionality and speed, not security. The resulting applications share predictable vulnerability signatures that attackers can systematically exploit.

---

## Methodology

### Discovery & Enumeration
- Scraped platform galleries (launched.lovable.dev, bolt.new/gallery, madewithbolt.com)
- Mined Certificate Transparency logs for platform-associated subdomains
- Fingerprinted applications to confirm AI-generated origin

### Scanning
- Security header analysis (CSP, HSTS, X-Frame-Options, X-Content-Type-Options)
- Client-side JavaScript bundle analysis for exposed secrets
- BaaS configuration probing (Supabase RLS, Firebase rules)
- Technology fingerprinting and source map detection

### Grading
Each application received a weighted security score (0–100) mapped to letter grades (A–F) based on the presence or absence of security controls.

---

## Repository Structure

```
vibe-code-security/
├── README.md                    # This file
├── METHODOLOGY.md               # Full research methodology
├── discovery/                   # App discovery & enumeration
│   ├── scrapers/                # Platform directory scrapers
│   ├── ct-logs/                 # Certificate Transparency mining
│   ├── fingerprinting/          # Vibe-code detection heuristics
│   └── pipeline.py              # Master orchestration
├── scanner/                     # Vulnerability scanning
│   ├── scan_orchestrator.py     # Lambda-based parallel scanning
│   ├── header_scanner.py        # Security header checks
│   ├── secret_scanner.py        # JS bundle secret detection
│   ├── baas_prober.py           # Supabase/Firebase RLS probe
│   └── grader.py                # A-F grade computation
├── analysis/                    # Statistical analysis
│   ├── analyze.py               # Main analysis script
│   ├── visualizations.py        # Chart generation
│   └── notebooks/               # Jupyter notebooks
├── article/                     # Scholarly article
│   ├── article.md               # Full article (Markdown)
│   └── figures/                 # Publication figures
└── data/                        # Anonymized dataset
    └── summary_statistics.json  # Aggregate findings
```

---

## Implications

### For Developers
If you've built with AI coding tools, assume your app is missing security controls. Run a security scan before going to production.

### For Platforms
AI coding tools should implement secure defaults: auto-inject CSP headers, warn on exposed secrets, enforce HTTPS.

### For Security Teams
Vibe-coded applications present a predictable attack surface. Prioritize header injection, client-side secret extraction, and BaaS misconfigurations in your assessments.

---

## Try SecureStack

This research powers **[SecureStack](https://securestackscan.com)**, a security assessment platform purpose-built for AI-generated applications.

- **Free Vibe-Code Health Check** — Scan any URL in 60 seconds
- **MVP Security Check ($450)** — GitHub repo deep scan with SAST/SCA
- **SOC2 Readiness ($2,500)** — Compliance mapping and auditor-ready docs
- **Managed CISO ($2,500/mo)** — Ongoing security program

👉 **[securestackscan.com](https://securestackscan.com)**

---

## Citation

```bibtex
@article{winters2026insecure,
  title={Insecure by Default: A Cross-Platform Security Analysis of AI-Generated Web Applications},
  author={Winters, Kirby and Merrill, Todd},
  year={2026},
  publisher={CyberSavi}
}
```

---

## Contact

- **Email:** research@cybersavi.com
- **SecureStack:** [securestackscan.com](https://securestackscan.com)
- **CyberSavi:** [cybersavi.com](https://cybersavi.com)

---

## License

Research findings and methodology are released under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). Code is released under MIT License.
