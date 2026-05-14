/**
 * Final email test — centered wordmark + mobile-optimized shell.
 * Sends the welcome email to verify the layout.
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

const logo = `<p style="margin:0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;font-size:22px;font-weight:800;color:#ffffff;letter-spacing:0.14em;text-transform:uppercase;text-align:center">SICARIO</p>`;

const content = `
  <h1 style="margin:0 0 8px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;font-size:24px;font-weight:700;color:${textPrimary};letter-spacing:-0.02em">Welcome, Test User 👋</h1>
  <p style="margin:0 0 24px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;font-size:15px;line-height:1.7;color:${textSecondary}">
    Your Sicario account is ready. Scan your codebase for vulnerabilities, publish results to the cloud dashboard, and fix them with AI-powered auto-remediation — all without your source code ever leaving your machine.
  </p>
  <table role="presentation" cellpadding="0" cellspacing="0" border="0" style="margin:0 0 28px;width:100%">
    <tr><td class="mobile-btn" style="border-radius:7px;background-color:${accent}">
      <a href="https://usesicario.xyz/dashboard" style="display:inline-block;padding:13px 28px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;font-size:14px;font-weight:700;color:#000;text-decoration:none;letter-spacing:0.01em">Go to Dashboard →</a>
    </td></tr>
  </table>
  <p style="margin:0 0 10px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;font-size:13px;font-weight:600;color:${textMuted};letter-spacing:0.06em;text-transform:uppercase">Get started in 30 seconds</p>
  <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="margin:0 0 8px;border-radius:7px;background-color:${bg};border:1px solid ${border}">
    <tr><td style="padding:14px 18px"><code style="font-family:'Courier New',Courier,monospace;font-size:13px;color:${accent}">curl -fsSL https://usesicario.xyz/install.sh | sh</code></td></tr>
  </table>
  <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="border-radius:7px;background-color:${bg};border:1px solid ${border}">
    <tr><td style="padding:14px 18px"><code style="font-family:'Courier New',Courier,monospace;font-size:13px;color:${accent}">sicario scan . --publish</code></td></tr>
  </table>`;

const html = `<!DOCTYPE html>
<html lang="en" xmlns="http://www.w3.org/1999/xhtml">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <meta http-equiv="X-UA-Compatible" content="IE=edge">
  <meta name="x-apple-disable-message-reformatting">
  <title>Sicario</title>
  <style>
    body,table,td,a{-webkit-text-size-adjust:100%;-ms-text-size-adjust:100%}
    table,td{mso-table-lspace:0pt;mso-table-rspace:0pt}
    body{margin:0;padding:0;background-color:${bg};width:100%!important}
    a{color:${accent}}
    @media only screen and (max-width:600px){
      .email-container{width:100%!important;min-width:100%!important}
      .email-header,.email-body,.email-footer{padding-left:20px!important;padding-right:20px!important}
      .email-header{padding-top:20px!important;padding-bottom:16px!important}
      .email-body{padding-top:28px!important;padding-bottom:28px!important}
      .mobile-btn{width:100%!important;display:block!important;text-align:center!important;box-sizing:border-box!important}
      h1{font-size:20px!important}
    }
  </style>
</head>
<body style="margin:0;padding:0;background-color:${bg}">
  <div style="display:none;font-size:1px;color:${bg};line-height:1px;max-height:0;overflow:hidden">Your Sicario account is ready.&nbsp;‌&nbsp;‌&nbsp;‌&nbsp;‌&nbsp;‌&nbsp;‌&nbsp;‌&nbsp;‌&nbsp;‌&nbsp;‌</div>
  <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="background-color:${bg}">
    <tr><td align="center" style="padding:32px 12px">
      <table class="email-container" role="presentation" cellpadding="0" cellspacing="0" border="0" width="560" style="max-width:560px;width:100%">

        <!-- Header -->
        <tr><td class="email-header" align="center" style="background-color:${surface};border:1px solid ${border};border-bottom:none;border-radius:12px 12px 0 0;padding:24px 40px 20px">
          ${logo}
        </td></tr>

        <!-- Divider -->
        <tr><td style="background-color:${surface};border-left:1px solid ${border};border-right:1px solid ${border}">
          <div style="height:1px;background-color:${borderSubtle};font-size:0;line-height:0">&nbsp;</div>
        </td></tr>

        <!-- Body -->
        <tr><td class="email-body" style="background-color:${surface};border-left:1px solid ${border};border-right:1px solid ${border};padding:32px 40px">
          ${content}
        </td></tr>

        <!-- Footer -->
        <tr><td class="email-footer" style="background-color:${surface};border:1px solid ${border};border-top:1px solid ${borderSubtle};border-radius:0 0 12px 12px;padding:18px 40px">
          <p style="margin:0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;font-size:12px;line-height:1.7;color:${textMuted};text-align:center">
            You're receiving this because you have a Sicario account.
            <br>
            <a href="https://usesicario.xyz" style="color:${textMuted};text-decoration:underline">usesicario.xyz</a>
            &nbsp;·&nbsp;
            <a href="https://usesicario.xyz/privacy" style="color:${textMuted};text-decoration:underline">Privacy Policy</a>
          </p>
        </td></tr>

      </table>
    </td></tr>
  </table>
</body></html>`;

const result = await r.emails.send({
  from: "Emmanuel from Sicario <noreply@usesicario.xyz>",
  to: "emmycodes234@gmail.com",
  subject: "Welcome to Sicario (final layout test)",
  html,
});

if (result.error) {
  console.error("FAILED:", result.error.message);
} else {
  console.log("✓ Sent  (id:", result.data?.id + ")");
  console.log("  Header: centered SICARIO wordmark");
  console.log("  Mobile: fluid width, 20px side padding, full-width CTA button");
}
