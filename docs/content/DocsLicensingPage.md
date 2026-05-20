> **Platform**

# Licensing

Sicario is governed by the **Functional Source License 1.1 (FSL-1.1)** with the **Apache License 2.0** serving as the Change License. This dual-license model balances open-source principles with commercial sustainability.

---

## FSL-1.1 (Functional Source License)

### What It Allows

Under FSL-1.1, you are free to:

- **Use Sicario locally** — Run the CLI on your development machine, in your CI/CD pipeline, or in any internal environment
- **Audit the source code** — The full source code is publicly available on GitHub for security review and transparency
- **Modify the source** — Fork the repository and make changes for your own use
- **Distribute internally** — Share the binary and source within your organization
- **Use in open source projects** — Scan your open source repositories without restriction
- **Use for consulting work** — Run Sicario for your clients' projects (as long as you are not offering a hosted scanning service)

### What It Restricts

The FSL-1.1 restricts **one specific use case**:

> **Third-party hosted commercial scanning**: You may not offer Sicario as a hosted, commercial security scanning service to third parties. This means you cannot build a SaaS product that wraps Sicario's scanning engine and sells it to other companies.

This restriction ensures that the Sicario team (the original developers) can sustain the project commercially while keeping the source code fully open for audit, local use, and modification.

### Conversion to Apache 2.0

**Two years after each version's first public release, the license for that version automatically converts to the permissive Apache 2.0 license.**

This means:

- Version 1.0 released January 2025 → converts to Apache 2.0 in January 2027
- Version 2.0 released June 2026 → converts to Apache 2.0 in June 2028

After conversion, that version becomes fully open source under Apache 2.0 — no restrictions whatsoever. This is a time-delayed open source model, similar to what HashiCorp (BSL) and other companies use.

### FSL-1.1 vs Other Licenses

| Aspect | FSL-1.1 | Apache 2.0 | GPL 3.0 | MIT |
|--------|---------|------------|---------|-----|
| Source code available | ✅ Yes | ✅ Yes | ✅ Yes | ✅ Yes |
| Free local use | ✅ Yes | ✅ Yes | ✅ Yes | ✅ Yes |
| Modify & fork | ✅ Yes | ✅ Yes | ✅ Yes | ✅ Yes |
| Internal distribution | ✅ Yes | ✅ Yes | ✅ Yes | ✅ Yes |
| Hosted commercial service | ❌ Restricted (2yr) | ✅ Yes | ✅ Yes | ✅ Yes |
| Copyleft requirements | ❌ No | ❌ No | ✅ Yes | ❌ No |
| Converts to permissive | ✅ After 2 years | N/A | N/A | N/A |

---

## Pricing Tiers

The Sicario Cloud dashboard operates on a freemium model. The **CLI is fully functional at every tier** — pricing only affects cloud dashboard features, retention, and team management.

### Free Tier

| Feature | Limit |
|---------|-------|
| CLI functionality | ✅ Full access (SAST, SCA, secrets, auto-remediation, reporting) |
| Cloud projects | 1 active project |
| Cloud findings | 500 stored findings |
| Data retention | 30 days |
| Team members | 1 (single user) |
| Reporting | CLI output only |

**Best for**: Individual developers, open source projects, personal use.

### Pro — $19/month

| Feature | Limit |
|---------|-------|
| Everything in Free | ✅ |
| Cloud projects | Up to 10 active projects |
| Cloud findings | Up to 5,000 stored findings |
| Data retention | 90 days |
| Notifications | Slack & Microsoft Teams webhooks |
| Report formats | SARIF & OWASP Top 10 download |

**Best for**: Small teams, startups, consultant developers managing multiple client projects.

### Team — $35/month

| Feature | Limit |
|---------|-------|
| Everything in Pro | ✅ |
| Cloud projects | Unlimited |
| Cloud findings | Unlimited |
| Data retention | 365 days |
| Team management | Invite members, assign roles (Admin / Member / Viewer) |
| Custom rules | Upload custom YAML rules via cloud dashboard |
| Baseline management | Full baseline trend visualization |
| Audit trail | Execution history per team member |

**Best for**: Security teams, engineering teams with multiple contributors, organizations requiring compliance tracking.

### Enterprise — Custom Pricing

| Feature | Details |
|---------|---------|
| Everything in Team | ✅ |
| SSO / SAML 2.0 | Integration with Okta, Azure AD, Google Workspace, OneLogin |
| OIDC support | OpenID Connect for custom identity providers |
| Compliance exports | SOC 2, ISO 27001, FedRAMP-ready data exports |
| Custom retention | Configurable retention periods (up to 7 years) |
| SLA | Guaranteed uptime and support response times |
| Dedicated support | Named support engineer, priority queue |
| Custom integrations | API access, webhook customization |

**Best for**: Large enterprises, regulated industries (finance, healthcare, government), organizations with compliance requirements.

### Tier Comparison

```
                 Free          Pro ($19/mo)    Team ($35/mo)   Enterprise
                 ─────         ────────────    ─────────────   ──────────
CLI              ✅ Full       ✅ Full         ✅ Full         ✅ Full
SAST/SCA/Secrets ✅ Full       ✅ Full         ✅ Full         ✅ Full
Auto-Remediation ✅ Full       ✅ Full         ✅ Full         ✅ Full
Projects         1             10              Unlimited       Unlimited
Findings         500           5,000           Unlimited       Unlimited
Retention        30 days       90 days         365 days        Custom
Notifications    —             Slack/Teams     Slack/Teams     +Webhook
SARIF/OWASP      —             ✅ Download     ✅ Download     ✅ +API
Team Mgmt        —             —              ✅              ✅ +SSO
Custom Rules     —             —              ✅              ✅
Baselines        —             —              ✅              ✅
Audit Trail      —             —              ✅              ✅
SLA              —             —              —              ✅
Dedicated Supp   —             —              —              ✅
```

### Which Tier for Which Use Case

| You are a... | Recommended Tier |
|--------------|------------------|
| Solo developer scanning personal projects | Free |
| Developer wanting cloud visibility + notifications | Pro |
| Small team (2-5 devs) with shared dashboard | Pro or Team |
| Security team managing multiple repos | Team |
| Large organization with compliance requirements | Enterprise |
| Consultant scanning multiple client projects | Pro |
| Open source maintainer | Free (unlimited scope on public repos) |

---

## How to Upgrade

### Pro / Team via Whop

1. Visit **[https://usesicario.xyz/pricing](https://usesicario.xyz/pricing)** or click **Upgrade** in the cloud dashboard
2. Select **Pro ($19/mo)** or **Team ($35/mo)**
3. Complete checkout via Whop (credit card or cryptocurrency)
4. Your Sicario Cloud dashboard is automatically upgraded — no configuration changes needed

### Enterprise

For Enterprise plans, contact the team:

- **Email**: [enterprise@usesicario.xyz](mailto:enterprise@usesicario.xyz)
- **Discord**: Join the [Sicario Discord](https://discord.gg/sicario) and ask in the `#enterprise` channel

Enterprise onboarding includes:

1. Initial consultation to understand your requirements
2. SSO/OIDC configuration
3. Custom retention policy setup
4. SLA documentation
5. Dedicated support onboarding

---

## Open Source & Community

### Rule Contributions

Sicario's rule set is open for community contributions. Rules are defined as YAML files with tree-sitter AST patterns:

```yaml
# Example custom rule: rules/js/no-dangerous-setinnerhtml.yaml
id: js/no-dangerous-setinnerhtml
message: "Setting innerHTML with unsanitized user input can lead to XSS"
severity: High
patterns:
  - pattern: "$X.innerHTML = $Y"
    filters:
      - not: "$Y is sanitized"
```

To contribute:

1. Fork the [Sicario CLI repository](https://github.com/sicario-labs/sicario-cli)
2. Add or modify rules in the `rules/` directory
3. Test with `sicario rules test`
4. Submit a pull request

### Reporting Issues

Found a bug, false positive, or missing rule? Open an issue on GitHub:

- **Bug reports**: Include the Sicario version (`sicario --version`), the file/code snippet (if safe to share), and the expected vs actual behavior
- **Feature requests**: Describe the vulnerability class or detection pattern you'd like supported
- **False positives**: Include the code, the finding details, and why it's incorrect

---

## License FAQ

### Can I use Sicario in my startup?

**Yes, absolutely.** If you're using Sicario to scan your own codebase (whether for a startup, side project, or Fortune 500), the FSL-1.1 allows full free use of the CLI. No license fee is required for scanning your own code.

You only need a paid plan if you want **cloud dashboard features** (multiple projects, longer retention, team management, notifications).

### Do I need a license for CI/CD?

**No.** The CLI is free to use in CI/CD pipelines. The Free tier includes full CLI functionality, including SARIF output, exit code gating, and baseline management. Cloud dashboard features (publishing results, team management, long-term retention) require a paid plan.

You can run this in your CI/CD pipeline without any license:

```yaml
# No license required for CI/CD usage
- name: Run Sicario
  run: sicario scan . --fail-on High --sarif-output results.sarif
```

### Can I use Sicario for consulting work?

**Yes.** If you are a consultant or agency scanning your clients' codebases, the FSL-1.1 allows this. The restriction only applies to offering Sicario as a **hosted commercial scanning service** to third parties (i.e., building a SaaS product around it).

### What counts as "third-party hosted commercial scanning"?

Offering Sicario's scanning capabilities as a service where:

- Customers upload their code to **your servers** for scanning
- You charge for scan execution or report generation
- Sicario runs as a backend component of your multi-tenant SaaS product

This does **not** include:

- Running Sicario on your own code or your client's code on your local machine
- Installing Sicario in a client's CI/CD pipeline
- Sharing scan results manually

### When does my version convert to Apache 2.0?

Each version converts exactly **2 years after its first public release**. The conversion is automatic — no action required on your part. You can check the release date and conversion date on the GitHub releases page.

### Can I modify and redistribute Sicario?

**Yes, under the FSL-1.1 terms.** You can fork, modify, and redistribute the source code internally or as part of your own products, as long as you do not offer it as a hosted commercial scanning service. After the 2-year conversion window, the Apache 2.0 license applies with no restrictions.

### Is the source code available for security audit?

**Yes.** The full source code is publicly available on [GitHub](https://github.com/sicario-labs/sicario-cli). Security researchers, penetration testers, and compliance auditors are encouraged to review the codebase. The FSL-1.1 explicitly allows source code auditing.

### What happens if I stop paying?

The **CLI continues to work** — it never phones home for license validation. You lose access to:

- Cloud dashboard (published findings, team management, historical data)
- Notifications (Slack, Teams)
- Extended retention (beyond your last paid period)

Your data is retained for 30 days after the subscription ends, then permanently deleted.

### Do I need a license for air-gapped environments?

**No.** Sicario's CLI operates fully offline. No license validation, no telemetry requirement, no cloud dependency for scanning. The CLI binary runs indefinitely without any network access. Cloud features (dashboard, notifications, team management) naturally require network access but are entirely optional.

---

## Related

- [Pricing Page](/pricing) — Detailed pricing comparison and checkout
- [GitHub Repository](https://github.com/sicario-labs/sicario-cli) — Source code and issue tracker
- [FSL-1.1 License](https://github.com/sicario-labs/sicario-cli/blob/main/LICENSE) — Full license text
- [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) — Change License text

---

## Next Steps

1. [Start using Sicario for free](./installation) — No sign-up required
2. [Compare plans](/pricing) — Find the tier that fits your needs
3. [Upgrade to Pro](https://whop.com/sicario-pro) — Unlock cloud dashboard features
4. [Contact Enterprise Sales](mailto:enterprise@usesicario.xyz) — For SSO, compliance, and custom needs
5. [Contribute a rule](https://github.com/sicario-labs/sicario-cli) — Help grow the detection library
