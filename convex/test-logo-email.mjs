/**
 * Sends one email to verify the updated logo renders correctly.
 */
import { Resend } from "resend";

const r = new Resend("re_fKs7kJ72_6VDjvCZ3cbvubgGgWU4kwzes");

const accent = "#ADFF2F";
const bg = "#0a0a0a";
const surface = "#111111";
const border = "#1f1f1f";
const borderSubtle = "#181818";
const textPrimary = "#f4f4f5";
const textSecondary = "#a1a1aa";
const textMuted = "#52525b";

const logo = `
<table cellpadding="0" cellspacing="0" border="0" role="presentation">
  <tr>
    <td style="vertical-align:middle;padding-right:12px">
      <svg width="36" height="36" viewBox="0 0 36 36" fill="none" xmlns="http://www.w3.org/2000/svg" style="display:block">
        <circle cx="18" cy="18" r="18" fill="${accent}"/>
        <path d="M18 0 A18 18 0 0 1 36 18 L18 18 Z" fill="rgba(0,0,0,0.18)"/>
        <line x1="25" y1="9" x2="11" y2="27" stroke="#000000" stroke-width="3.5" stroke-linecap="round"/>
      </svg>
    </td>
    <td style="vertical-align:middle">
      <span style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;font-size:20px;font-weight:800;color:#ffffff;letter-spacing:0.1em;text-transform:uppercase">SICARIO</span>
    </td>
  </tr>
</table>`;

const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Sicario</title>
</head>
<body style="margin:0;padding:0;background-color:${bg};font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif">
  <div style="display:none;font-size:1px;color:${bg};line-height:1px;max-height:0;overflow:hidden">Welcome to Sicario — your account is ready.</div>
  <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="background-color:${bg}">
    <tr><td align="center" style="padding:40px 16px">
      <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="560" style="max-width:560px;width:100%">

        <!-- Header with logo -->
        <tr><td style="background-color:${surface};border:1px solid ${border};border-bottom:none;border-radius:12px 12px 0 0;padding:28px 40px 24px">
          ${logo}
        </td></tr>

        <!-- Divider -->
        <tr><td style="background-color:${surface};border-left:1px solid ${border};border-right:1px solid ${border};padding:0 40px">
          <div style="height:1px;background-color:${borderSubtle}">&nbsp;</div>
        </td></tr>

        <!-- Body -->
        <tr><td style="background-color:${surface};border-left:1px solid ${border};border-right:1px solid ${border};padding:36px 40px">
          <h1 style="margin:0 0 8px;font-size:24px;font-weight:700;color:${textPrimary};letter-spacing:-0.02em">Welcome, Test User 👋</h1>
          <p style="margin:0 0 24px;font-size:15px;line-height:1.7;color:${textSecondary}">
            Your Sicario account is ready. Scan your codebase for vulnerabilities, publish results to the cloud dashboard, and fix them with AI-powered auto-remediation — all without your source code ever leaving your machine.
          </p>
          <table role="presentation" cellpadding="0" cellspacing="0" border="0" style="margin:0 0 28px">
            <tr><td style="border-radius:7px;background-color:${accent}">
              <a href="https://usesicario.xyz/dashboard" style="display:inline-block;padding:13px 28px;font-size:14px;font-weight:700;color:#000;text-decoration:none;letter-spacing:0.01em">Go to Dashboard →</a>
            </td></tr>
          </table>
          <p style="margin:0 0 10px;font-size:13px;font-weight:600;color:${textMuted};letter-spacing:0.06em;text-transform:uppercase">Get started in 30 seconds</p>
          <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="margin:0 0 8px;border-radius:7px;background-color:${bg};border:1px solid ${border}">
            <tr><td style="padding:14px 18px"><code style="font-size:13px;color:${accent}">curl -fsSL https://usesicario.xyz/install.sh | sh</code></td></tr>
          </table>
          <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="border-radius:7px;background-color:${bg};border:1px solid ${border}">
            <tr><td style="padding:14px 18px"><code style="font-size:13px;color:${accent}">sicario scan . --publish</code></td></tr>
          </table>
        </td></tr>

        <!-- Footer -->
        <tr><td style="background-color:${surface};border:1px solid ${border};border-top:1px solid ${borderSubtle};border-radius:0 0 12px 12px;padding:20px 40px">
          <p style="margin:0;font-size:12px;line-height:1.6;color:${textMuted}">
            You're receiving this because you have a Sicario account.
            &nbsp;·&nbsp;<a href="https://usesicario.xyz" style="color:${textMuted};text-decoration:underline">usesicario.xyz</a>
            &nbsp;·&nbsp;<a href="https://usesicario.xyz/privacy" style="color:${textMuted};text-decoration:underline">Privacy Policy</a>
          </p>
        </td></tr>

      </table>
    </td></tr>
  </table>
</body></html>`;

const result = await r.emails.send({
  from: "Emmanuel from Sicario <noreply@usesicario.xyz>",
  to: "emmycodes234@gmail.com",
  subject: "Welcome to Sicario (logo test)",
  html,
});

if (result.error) {
  console.error("FAILED:", result.error.message);
} else {
  console.log("✓ Logo test email sent  (id:", result.data?.id + ")");
  console.log("  Check emmycodes234@gmail.com — the logo should show a lime-green circle with a diagonal slash + SICARIO wordmark.");
}
