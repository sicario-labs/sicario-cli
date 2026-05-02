/**
 * Transactional email sending via Resend.
 *
 * All emails are sent from noreply@usesicario.xyz.
 * Set RESEND_API_KEY in your Convex environment variables.
 *
 * Free tier: 3,000 emails/month, no credit card required.
 * Sign up at https://resend.com and add your domain.
 */

import { Resend } from "resend";

function getResend(): Resend {
  const key = process.env.RESEND_API_KEY;
  if (!key) {
    throw new Error(
      "RESEND_API_KEY is not set. Add it via `npx convex env set RESEND_API_KEY re_...`"
    );
  }
  return new Resend(key);
}

const FROM = "Sicario <noreply@usesicario.xyz>";

// ── Welcome email ─────────────────────────────────────────────────────────────

export async function sendWelcomeEmail(to: string, name?: string): Promise<void> {
  const resend = getResend();
  const displayName = name ?? to.split("@")[0];

  await resend.emails.send({
    from: FROM,
    to,
    subject: "Welcome to Sicario",
    html: `
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:#0a0a0a;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;color:#d4d4d4">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#0a0a0a;padding:40px 20px">
    <tr><td align="center">
      <table width="560" cellpadding="0" cellspacing="0" style="background:#111;border:1px solid #222;border-radius:12px;overflow:hidden;max-width:560px;width:100%">
        <!-- Header -->
        <tr><td style="padding:32px 40px 24px;border-bottom:1px solid #1a1a1a">
          <table cellpadding="0" cellspacing="0"><tr>
            <td style="width:24px;height:24px;background:#ADFF2F;border-radius:50%;vertical-align:middle"></td>
            <td style="padding-left:10px;font-size:18px;font-weight:700;color:#fff;letter-spacing:0.05em;text-transform:uppercase;vertical-align:middle">SICARIO</td>
          </tr></table>
        </td></tr>
        <!-- Body -->
        <tr><td style="padding:32px 40px">
          <h1 style="margin:0 0 16px;font-size:22px;font-weight:600;color:#fff">Welcome, ${displayName}</h1>
          <p style="margin:0 0 20px;font-size:15px;line-height:1.6;color:#a3a3a3">
            Your Sicario account is ready. You can now scan your codebase for vulnerabilities, publish results to the cloud dashboard, and use AI-powered auto-remediation.
          </p>
          <table cellpadding="0" cellspacing="0" style="margin:0 0 24px">
            <tr><td style="background:#ADFF2F;border-radius:6px;padding:12px 24px">
              <a href="https://usesicario.xyz/dashboard" style="color:#000;font-size:14px;font-weight:700;text-decoration:none;display:block">Go to Dashboard →</a>
            </td></tr>
          </table>
          <p style="margin:0 0 12px;font-size:13px;color:#737373">Get started in 30 seconds:</p>
          <table cellpadding="0" cellspacing="0" style="background:#0a0a0a;border:1px solid #1a1a1a;border-radius:8px;width:100%">
            <tr><td style="padding:16px 20px;font-family:'Courier New',monospace;font-size:13px;color:#ADFF2F">
              curl -fsSL https://usesicario.xyz/install.sh | sh<br>
              sicario scan .
            </td></tr>
          </table>
        </td></tr>
        <!-- Footer -->
        <tr><td style="padding:20px 40px;border-top:1px solid #1a1a1a">
          <p style="margin:0;font-size:12px;color:#525252">
            You're receiving this because you created a Sicario account.<br>
            <a href="https://usesicario.xyz" style="color:#737373">usesicario.xyz</a>
          </p>
        </td></tr>
      </table>
    </td></tr>
  </table>
</body>
</html>`,
  });
}

// ── Password reset OTP email ──────────────────────────────────────────────────

export async function sendPasswordResetEmail(
  to: string,
  otp: string
): Promise<void> {
  const resend = getResend();

  await resend.emails.send({
    from: FROM,
    to,
    subject: "Reset your Sicario password",
    html: `
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:#0a0a0a;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;color:#d4d4d4">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#0a0a0a;padding:40px 20px">
    <tr><td align="center">
      <table width="560" cellpadding="0" cellspacing="0" style="background:#111;border:1px solid #222;border-radius:12px;overflow:hidden;max-width:560px;width:100%">
        <!-- Header -->
        <tr><td style="padding:32px 40px 24px;border-bottom:1px solid #1a1a1a">
          <table cellpadding="0" cellspacing="0"><tr>
            <td style="width:24px;height:24px;background:#ADFF2F;border-radius:50%;vertical-align:middle"></td>
            <td style="padding-left:10px;font-size:18px;font-weight:700;color:#fff;letter-spacing:0.05em;text-transform:uppercase;vertical-align:middle">SICARIO</td>
          </tr></table>
        </td></tr>
        <!-- Body -->
        <tr><td style="padding:32px 40px">
          <h1 style="margin:0 0 16px;font-size:22px;font-weight:600;color:#fff">Reset your password</h1>
          <p style="margin:0 0 24px;font-size:15px;line-height:1.6;color:#a3a3a3">
            Use the code below to reset your password. It expires in <strong style="color:#fff">1 hour</strong>.
          </p>
          <!-- OTP block -->
          <table cellpadding="0" cellspacing="0" style="margin:0 0 24px;width:100%">
            <tr><td align="center" style="background:#0a0a0a;border:1px solid #1a1a1a;border-radius:8px;padding:24px">
              <span style="font-family:'Courier New',monospace;font-size:32px;font-weight:700;letter-spacing:0.15em;color:#ADFF2F">${otp}</span>
            </td></tr>
          </table>
          <p style="margin:0;font-size:13px;color:#737373">
            If you didn't request a password reset, you can safely ignore this email. Your password won't change.
          </p>
        </td></tr>
        <!-- Footer -->
        <tr><td style="padding:20px 40px;border-top:1px solid #1a1a1a">
          <p style="margin:0;font-size:12px;color:#525252">
            This code expires in 1 hour.<br>
            <a href="https://usesicario.xyz" style="color:#737373">usesicario.xyz</a>
          </p>
        </td></tr>
      </table>
    </td></tr>
  </table>
</body>
</html>`,
  });
}
