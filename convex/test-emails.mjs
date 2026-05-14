/**
 * Direct email test — calls Resend API without going through `npx convex run`.
 * Usage: node test-emails.mjs
 */

import { Resend } from "resend";

const RESEND_API_KEY = "re_fKs7kJ72_6VDjvCZ3cbvubgGgWU4kwzes";
const TO = "emmycodes234@gmail.com";
const FROM = "Emmanuel from Sicario <noreply@usesicario.xyz>";

const resend = new Resend(RESEND_API_KEY);

const colors = {
  bg: "#0a0a0a",
  surface: "#111111",
  border: "#1f1f1f",
  borderSubtle: "#181818",
  accent: "#ADFF2F",
  textPrimary: "#f4f4f5",
  textSecondary: "#a1a1aa",
  textMuted: "#52525b",
  codeBg: "#0a0a0a",
  codeText: "#ADFF2F",
};

function shell(content, preview) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Sicario</title>
  <style>
    body { margin:0; padding:0; background-color:${colors.bg}; font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif; }
    a { color:${colors.accent}; }
  </style>
</head>
<body style="margin:0;padding:0;background-color:${colors.bg}">
  <div style="display:none;font-size:1px;color:${colors.bg};line-height:1px;max-height:0;overflow:hidden">${preview}</div>
  <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="background-color:${colors.bg}">
    <tr><td align="center" style="padding:40px 16px">
      <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="560" style="max-width:560px;width:100%">
        <!-- Header -->
        <tr><td style="background-color:${colors.surface};border:1px solid ${colors.border};border-bottom:none;border-radius:12px 12px 0 0;padding:28px 40px 24px">
          <table cellpadding="0" cellspacing="0" border="0"><tr>
            <td style="padding-right:10px">
              <svg width="28" height="28" viewBox="0 0 28 28" fill="none" xmlns="http://www.w3.org/2000/svg">
                <circle cx="14" cy="14" r="14" fill="${colors.accent}"/>
                <line x1="20" y1="7" x2="8" y2="21" stroke="#000" stroke-width="3" stroke-linecap="round"/>
              </svg>
            </td>
            <td><span style="font-size:18px;font-weight:800;color:#fff;letter-spacing:0.08em;text-transform:uppercase">SICARIO</span></td>
          </tr></table>
        </td></tr>
        <!-- Divider -->
        <tr><td style="background-color:${colors.surface};border-left:1px solid ${colors.border};border-right:1px solid ${colors.border};padding:0 40px">
          <div style="height:1px;background-color:${colors.borderSubtle}">&nbsp;</div>
        </td></tr>
        <!-- Body -->
        <tr><td style="background-color:${colors.surface};border-left:1px solid ${colors.border};border-right:1px solid ${colors.border};padding:36px 40px">
          ${content}
        </td></tr>
        <!-- Footer -->
        <tr><td style="background-color:${colors.surface};border:1px solid ${colors.border};border-top:1px solid ${colors.borderSubtle};border-radius:0 0 12px 12px;padding:20px 40px">
          <p style="margin:0;font-size:12px;color:${colors.textMuted}">
            You're receiving this because you have a Sicario account.
            &nbsp;·&nbsp;<a href="https://usesicario.xyz" style="color:${colors.textMuted}">usesicario.xyz</a>
          </p>
        </td></tr>
      </table>
    </td></tr>
  </table>
</body></html>`;
}

const emails = [
  {
    subject: "Welcome to Sicario",
    preview: "Your Sicario account is ready.",
    html: shell(`
      <h1 style="margin:0 0 8px;font-size:24px;font-weight:700;color:${colors.textPrimary}">Welcome, Test User 👋</h1>
      <p style="margin:0 0 24px;font-size:15px;line-height:1.7;color:${colors.textSecondary}">
        Your Sicario account is ready. Scan your codebase for vulnerabilities, publish results to the cloud dashboard, and fix them with AI-powered auto-remediation — all without your source code ever leaving your machine.
      </p>
      <table role="presentation" cellpadding="0" cellspacing="0" border="0" style="margin:0 0 28px">
        <tr><td style="border-radius:7px;background-color:${colors.accent}">
          <a href="https://usesicario.xyz/dashboard" style="display:inline-block;padding:13px 28px;font-size:14px;font-weight:700;color:#000;text-decoration:none">Go to Dashboard →</a>
        </td></tr>
      </table>
      <p style="margin:0 0 10px;font-size:13px;font-weight:600;color:${colors.textMuted};letter-spacing:0.06em;text-transform:uppercase">Get started in 30 seconds</p>
      <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="margin:0 0 8px;border-radius:7px;background-color:${colors.codeBg};border:1px solid ${colors.border}">
        <tr><td style="padding:14px 18px"><code style="font-size:13px;color:${colors.codeText}">curl -fsSL https://usesicario.xyz/install.sh | sh</code></td></tr>
      </table>
      <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="border-radius:7px;background-color:${colors.codeBg};border:1px solid ${colors.border}">
        <tr><td style="padding:14px 18px"><code style="font-size:13px;color:${colors.codeText}">sicario scan . --publish</code></td></tr>
      </table>
    `, "Your Sicario account is ready."),
  },
  {
    subject: "Reset your Sicario password",
    preview: "Your password reset code is inside.",
    html: shell(`
      <h1 style="margin:0 0 8px;font-size:24px;font-weight:700;color:${colors.textPrimary}">Reset your password</h1>
      <p style="margin:0 0 28px;font-size:15px;line-height:1.7;color:${colors.textSecondary}">
        Use the code below — it expires in <strong style="color:${colors.textPrimary}">1 hour</strong>.
      </p>
      <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="margin:0 0 28px">
        <tr><td align="center" style="background-color:${colors.codeBg};border:1px solid ${colors.border};border-radius:10px;padding:28px 20px">
          <p style="margin:0 0 6px;font-size:11px;font-weight:600;letter-spacing:0.1em;text-transform:uppercase;color:${colors.textMuted}">Your reset code</p>
          <span style="font-family:'Courier New',monospace;font-size:38px;font-weight:700;letter-spacing:0.2em;color:${colors.accent}">123456</span>
        </td></tr>
      </table>
      <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%">
        <tr><td style="padding:14px 16px;background-color:#0f1a00;border:1px solid #2a3d00;border-radius:7px">
          <p style="margin:0;font-size:13px;line-height:1.6;color:#8aad3a">
            <strong style="color:${colors.accent}">Didn't request this?</strong> You can safely ignore this email.
          </p>
        </td></tr>
      </table>
    `, "Your password reset code is inside."),
  },
  {
    subject: "You've been invited to Acme Corp on Sicario",
    preview: "Alice invited you to join Acme Corp",
    html: shell(`
      <h1 style="margin:0 0 8px;font-size:24px;font-weight:700;color:${colors.textPrimary}">You've been invited</h1>
      <p style="margin:0 0 24px;font-size:15px;line-height:1.7;color:${colors.textSecondary}">
        <strong style="color:${colors.textPrimary}">Alice (alice@acme.com)</strong> has invited you to join
        <strong style="color:${colors.textPrimary}">Acme Corp</strong> on Sicario as a
        <strong style="color:${colors.textPrimary}">developer</strong>.
      </p>
      <table role="presentation" cellpadding="0" cellspacing="0" border="0" style="margin:0 0 28px">
        <tr><td style="border-radius:7px;background-color:${colors.accent}">
          <a href="https://usesicario.xyz/auth?redirect=/dashboard" style="display:inline-block;padding:13px 28px;font-size:14px;font-weight:700;color:#000;text-decoration:none">Accept Invitation →</a>
        </td></tr>
      </table>
      <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%">
        <tr><td style="padding:14px 16px;background-color:#0f1a00;border:1px solid #2a3d00;border-radius:7px">
          <p style="margin:0;font-size:13px;color:#8aad3a">If you weren't expecting this invitation, you can safely ignore it.</p>
        </td></tr>
      </table>
    `, "Alice invited you to join Acme Corp"),
  },
  {
    subject: "[Sicario Alert] 3 critical findings in my-app",
    preview: "New critical security findings detected in my-app",
    html: shell(`
      <h1 style="margin:0 0 8px;font-size:24px;font-weight:700;color:${colors.textPrimary}">Security findings detected</h1>
      <p style="margin:0 0 24px;font-size:15px;line-height:1.7;color:${colors.textSecondary}">
        A scan of <strong style="color:${colors.textPrimary}">my-app</strong> detected findings that require immediate attention.
      </p>
      <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="margin:0 0 28px">
        <tr>
          <td style="padding:0 6px 0 0" width="33%">
            <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%">
              <tr><td style="background-color:${colors.codeBg};border:1px solid #4a1010;border-radius:8px;padding:16px 12px;text-align:center">
                <p style="margin:0 0 4px;font-size:11px;font-weight:600;letter-spacing:0.08em;text-transform:uppercase;color:#f87171">Critical</p>
                <span style="font-size:28px;font-weight:800;color:#f87171">3</span>
              </td></tr>
            </table>
          </td>
          <td style="padding:0 6px" width="33%">
            <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%">
              <tr><td style="background-color:${colors.codeBg};border:1px solid #4a2e10;border-radius:8px;padding:16px 12px;text-align:center">
                <p style="margin:0 0 4px;font-size:11px;font-weight:600;letter-spacing:0.08em;text-transform:uppercase;color:#fb923c">High</p>
                <span style="font-size:28px;font-weight:800;color:#fb923c">7</span>
              </td></tr>
            </table>
          </td>
          <td style="padding:0 0 0 6px" width="33%">
            <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%">
              <tr><td style="background-color:${colors.codeBg};border:1px solid ${colors.border};border-radius:8px;padding:16px 12px;text-align:center">
                <p style="margin:0 0 4px;font-size:11px;font-weight:600;letter-spacing:0.08em;text-transform:uppercase;color:${colors.textMuted}">Total</p>
                <span style="font-size:28px;font-weight:800;color:${colors.textPrimary}">14</span>
              </td></tr>
            </table>
          </td>
        </tr>
      </table>
      <table role="presentation" cellpadding="0" cellspacing="0" border="0" style="margin:0 0 20px">
        <tr><td style="border-radius:7px;background-color:${colors.accent}">
          <a href="https://usesicario.xyz/dashboard/findings" style="display:inline-block;padding:13px 28px;font-size:14px;font-weight:700;color:#000;text-decoration:none">View Findings →</a>
        </td></tr>
      </table>
      <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="border-radius:7px;background-color:${colors.codeBg};border:1px solid ${colors.border}">
        <tr><td style="padding:12px 16px"><code style="font-size:12px;color:${colors.textSecondary}">https://github.com/acme/my-app</code></td></tr>
      </table>
    `, "New critical security findings detected in my-app"),
  },
  {
    subject: "Sicario Weekly Digest — Acme Corp",
    preview: "Your weekly security summary is ready",
    html: shell(`
      <h1 style="margin:0 0 4px;font-size:24px;font-weight:700;color:${colors.textPrimary}">Weekly Security Digest</h1>
      <p style="margin:0 0 28px;font-size:14px;color:${colors.textMuted}">Acme Corp &nbsp;·&nbsp; May 3 – May 10, 2026</p>
      <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="margin:0 0 28px">
        <tr>
          <td style="padding:0 6px 12px 0" width="50%">
            <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%">
              <tr><td style="background-color:${colors.codeBg};border:1px solid ${colors.border};border-radius:8px;padding:16px">
                <p style="margin:0 0 4px;font-size:11px;font-weight:600;letter-spacing:0.08em;text-transform:uppercase;color:${colors.textMuted}">New Findings</p>
                <span style="font-size:28px;font-weight:800;color:${colors.textPrimary}">12</span>
              </td></tr>
            </table>
          </td>
          <td style="padding:0 0 12px 6px" width="50%">
            <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%">
              <tr><td style="background-color:${colors.codeBg};border:1px solid #4a1010;border-radius:8px;padding:16px">
                <p style="margin:0 0 4px;font-size:11px;font-weight:600;letter-spacing:0.08em;text-transform:uppercase;color:#f87171">Critical Open</p>
                <span style="font-size:28px;font-weight:800;color:#f87171">2</span>
              </td></tr>
            </table>
          </td>
        </tr>
        <tr>
          <td style="padding:0 6px 0 0" width="50%">
            <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%">
              <tr><td style="background-color:${colors.codeBg};border:1px solid #1a3d1a;border-radius:8px;padding:16px">
                <p style="margin:0 0 4px;font-size:11px;font-weight:600;letter-spacing:0.08em;text-transform:uppercase;color:#4ade80">Fixed This Week</p>
                <span style="font-size:28px;font-weight:800;color:#4ade80">8</span>
              </td></tr>
            </table>
          </td>
          <td style="padding:0 0 0 6px" width="50%">
            <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%">
              <tr><td style="background-color:${colors.codeBg};border:1px solid ${colors.border};border-radius:8px;padding:16px">
                <p style="margin:0 0 4px;font-size:11px;font-weight:600;letter-spacing:0.08em;text-transform:uppercase;color:${colors.textMuted}">Scans Run</p>
                <span style="font-size:28px;font-weight:800;color:${colors.textPrimary}">4</span>
              </td></tr>
            </table>
          </td>
        </tr>
      </table>
      <p style="margin:0 0 24px;font-size:14px;line-height:1.6;color:${colors.textSecondary}">
        Most active project: <strong style="color:${colors.textPrimary}">my-app</strong>
      </p>
      <table role="presentation" cellpadding="0" cellspacing="0" border="0">
        <tr><td style="border-radius:7px;background-color:${colors.accent}">
          <a href="https://usesicario.xyz/dashboard" style="display:inline-block;padding:13px 28px;font-size:14px;font-weight:700;color:#000;text-decoration:none">View Dashboard →</a>
        </td></tr>
      </table>
    `, "Your weekly security summary is ready"),
  },
];

console.log(`Sending ${emails.length} test emails to ${TO}...\n`);

for (const email of emails) {
  try {
    const result = await resend.emails.send({
      from: FROM,
      to: TO,
      subject: email.subject,
      html: email.html,
    });
    if (result.error) {
      console.error(`✗ FAILED  "${email.subject}"\n  Error: ${result.error.message}`);
    } else {
      console.log(`✓ Sent    "${email.subject}"  (id: ${result.data?.id})`);
    }
  } catch (err) {
    console.error(`✗ FAILED  "${email.subject}"\n  ${err.message}`);
  }
}

console.log("\nDone. Check emmycodes234@gmail.com inbox (and spam folder).");
