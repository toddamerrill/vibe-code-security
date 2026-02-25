# We Scanned 600 Vibe-Coded Apps. Here's What We Found.

**TL;DR:** 92% of vibe-coded apps get a C grade — not failing, but "just okay." The good news: nobody is leaking their Supabase service keys anymore. The bad news: 98% of apps are missing basic security headers that take 5 minutes to add. The ecosystem has settled into comfortable mediocrity.

---

## The Vibe Coding Security Question

If you've shipped an app with Lovable, Bolt, Replit, or any other AI coding tool, you've probably wondered: *Is this thing actually secure?*

We wondered too. So we built a scanner and pointed it at 603 production vibe-coded applications to find out.

Here's what we learned.

---

## The Big Picture: C Students Everywhere

| Grade | Apps | Percentage |
|-------|------|------------|
| A | 0 | 0% |
| B | 16 | 2.7% |
| **C** | **553** | **91.7%** |
| D | 30 | 5.0% |
| F | 4 | 0.7% |

**Average score: 75.3/100**

The pattern is striking: almost every app lands in the same narrow "Fair" band. No one's failing catastrophically. But almost no one's doing well either.

This is what "mediocre by default" looks like.

---

## The Good News First

### Your Secrets Are (Mostly) Safe

Remember the panic last year when researchers found Supabase service role keys littered across vibe-coded apps? That's basically fixed now.

| What We Checked | Result |
|-----------------|--------|
| Apps exposing service_role key | **0** (0%) |
| Apps with critical secrets in JS | 4 (0.7%) |
| Apps properly handling secrets | 558 (92.5%) |

**Why this matters:** The service_role key bypasses all Row-Level Security. Exposing it means anyone can read and write your entire database. The fact that zero apps in our sample exposed this key suggests platforms have added effective guardrails.

### Platform Infrastructure Is Doing Its Job

Some security headers showed near-universal adoption:

| Header | Adoption |
|--------|----------|
| Strict-Transport-Security (HTTPS) | 100% |
| X-Content-Type-Options | 93.5% |
| Referrer-Policy | 93.2% |

These are configured at the platform level (Vercel, Netlify, Lovable's infrastructure), not in your app code. When platforms handle security, it works.

---

## The Bad News: Your Headers Are a Mess

Here's where things get ugly:

| Header | Adoption | Missing |
|--------|----------|---------|
| Content-Security-Policy | **1.5%** | 592 apps |
| X-Frame-Options | **1.5%** | 592 apps |
| Permissions-Policy | **0.0%** | 601 apps |
| Cache-Control | 9.8% | 542 apps |

**98% of vibe-coded apps have no Content-Security-Policy.**

This is the header that prevents XSS attacks, stops malicious scripts from running, and is considered table-stakes security for any production web app.

### Why Does This Happen?

The pattern tells the story:
- **Headers that platforms configure automatically:** 93-100% adoption
- **Headers that require app-level config:** 0-10% adoption

AI code generators don't add security headers. Vibe coders don't know they need them. And platforms haven't (yet) made them default.

---

## The 5-Minute Fix

Here's how to go from C to A:

### For Vercel (vercel.json)

```json
{
  "headers": [
    {
      "source": "/(.*)",
      "headers": [
        {
          "key": "Content-Security-Policy",
          "value": "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline';"
        },
        {
          "key": "X-Frame-Options",
          "value": "DENY"
        },
        {
          "key": "X-Content-Type-Options",
          "value": "nosniff"
        },
        {
          "key": "Permissions-Policy",
          "value": "camera=(), microphone=(), geolocation=()"
        }
      ]
    }
  ]
}
```

### For Netlify (_headers file)

```
/*
  Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline';
  X-Frame-Options: DENY
  X-Content-Type-Options: nosniff
  Permissions-Policy: camera=(), microphone=(), geolocation=()
```

### For Lovable Apps

Add a `public/_headers` file or configure in your deployment settings. If you're on the default Lovable subdomain, you're dependent on their infrastructure defaults (which currently don't include CSP).

---

## Platform Comparison: Lovable vs. Replit

We had enough data to compare the two largest platforms in our sample:

| Platform | Apps | Avg Score | % Grade D or F |
|----------|------|-----------|----------------|
| Lovable | 587 | 75.4 | 4.9% |
| Replit | 15 | 70.8 | 33.3% |

**Lovable apps are more consistent.** Only 4.9% scored D or F, compared to 33.3% of Replit apps.

This likely reflects Lovable's more opinionated infrastructure — when the platform makes decisions for you, those decisions tend to be reasonable defaults. Replit's more flexible architecture leaves more room for misconfiguration.

---

## What's Actually Vulnerable?

Ranked by how many apps are affected:

| Issue | % Affected |
|-------|------------|
| Missing Permissions-Policy | 99.7% |
| Missing X-XSS-Protection | 99.5% |
| Missing Content-Security-Policy | 98.2% |
| Missing X-Frame-Options | 98.2% |
| Missing Cache-Control | 89.9% |
| Critical secrets exposed | 0.7% |

The top 5 issues are all **missing headers** — not misconfigurations, not exposed databases, not leaked credentials. Just... headers that were never added.

---

## The Real Problem: "Just Okay" Is the New Standard

Here's what concerns us most: the vibe coding ecosystem has settled into comfortable mediocrity.

- **Only 0.7% F grades** = platforms have prevented catastrophic failures
- **No A grades** = no one is implementing defense-in-depth
- **92% C grades** = everyone clusters around "just okay"

This creates a dangerous illusion. Developers ship their vibe-coded apps, see them working, and assume they're production-ready. But a C grade means "Fair" — it's a passing grade in school, but it's not what you want protecting your users' data.

A C-grade app is one XSS vulnerability away from a security incident. Without CSP, there's no second line of defense. That's 92% of the ecosystem.

---

## What Should Change

### Platforms Need To:

1. **Add CSP by default** — even a permissive report-only policy is better than nothing
2. **Show security status** — a simple dashboard showing header coverage
3. **Scan before deploy** — warn on missing protections before publishing

### AI Code Generators Need To:

1. **Include security headers** in generated deployment configs
2. **Generate RLS policies** alongside database tables
3. **Treat security as a first-class output**, not an afterthought

### You Need To:

1. **Add headers** — 5 minutes of work, massive security improvement
2. **Scan your app** — tools like [SecureStackScan.com](https://securestackscan.com) exist for automated security assessment
3. **Understand your BaaS** — if you're using Supabase, understand RLS; if Firebase, understand Security Rules
4. **Don't trust "it works" as "it's secure"**

---

## How We Did This

We built a discovery pipeline that found 15,823 potential vibe-coded apps through:
- Certificate Transparency logs
- Platform directories (launched.lovable.dev, bolt.new/gallery)
- GitHub README mining
- Reddit/social media scraping

After deduplication, liveness checks, and filtering, we had 603 confirmed live vibe-coded applications.

Each app was scanned across 5 categories:
- Security headers (8 checks)
- Exposed secrets (15+ patterns)
- BaaS configuration (RLS testing)
- Authentication security
- Application security (CORS, source maps, etc.)

Weighted scores produced letter grades A-F.

Full methodology in [our research paper](../article/article.md).

---

## The Bottom Line

Vibe coding has matured past the "everything is broken" phase. The catastrophic vulnerabilities from 2025 — exposed service role keys, wide-open databases — have been largely addressed.

But the ecosystem has stalled at "just okay." 92% of apps get a C grade. 98% are missing basic security headers that any traditional web developer would add without thinking.

A C isn't good enough for production. The fix is simple. The question is whether platforms will make security the default, or leave it to developers who may not know it's needed.

Until then: **add your headers, scan your apps, and don't assume the AI got security right.**

---

## Resources

- **Scan your app:** [SecureStackScan.com](https://securestackscan.com)
- **CSP Generator:** [CSP Evaluator](https://csp-evaluator.withgoogle.com)
- **Supabase RLS Guide:** [Row Level Security docs](https://supabase.com/docs/guides/auth/row-level-security)
- **Full Research Paper:** [Insecure by Default: A Cross-Platform Security Analysis](../article/article.md)

---

*This research was conducted by the CyberSavi security research team. Data collected February 2026. Individual application data is not published to protect potentially vulnerable deployments.*

*Questions? Contact todd@techcxo.com*
