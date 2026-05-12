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
import { action } from "./_generated/server";
import { v } from "convex/values";

function getResend(): Resend {
  const key = process.env.RESEND_API_KEY;
  if (!key) {
    throw new Error(
      "RESEND_API_KEY is not set. Add it via `npx convex env set RESEND_API_KEY re_...`"
    );
  }
  return new Resend(key);
}

const FROM = "Emmanuel from Sicario <noreply@usesicario.xyz>";

// ── Shared design tokens ──────────────────────────────────────────────────────

const colors = {
  bg: "#0a0a0a",
  surface: "#111111",
  border: "#1f1f1f",
  borderSubtle: "#181818",
  accent: "#ADFF2F",
  accentDark: "#8fd400",
  textPrimary: "#f4f4f5",
  textSecondary: "#a1a1aa",
  textMuted: "#52525b",
  codeText: "#ADFF2F",
  codeBg: "#0a0a0a",
};

// ── Logo / header ─────────────────────────────────────────────────────────────
// Centered SICARIO wordmark — no image dependency, renders everywhere.

function logoHtml(): string {
  return `<p style="margin:0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;font-size:22px;font-weight:800;color:#ffffff;letter-spacing:0.14em;text-transform:uppercase;text-align:center">SICARIO</p>`;
}

// ── Shared email shell ────────────────────────────────────────────────────────
// Mobile-first: single-column, fluid width, 16px side padding on small screens,
// readable font sizes, full-width CTA buttons on mobile.

function emailShell(content: string, previewText: string): string {
  return `<!DOCTYPE html>
<html lang="en" xmlns="http://www.w3.org/1999/xhtml" xmlns:v="urn:schemas-microsoft-com:vml" xmlns:o="urn:schemas-microsoft-com:office:office">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <meta http-equiv="X-UA-Compatible" content="IE=edge">
  <meta name="x-apple-disable-message-reformatting">
  <title>Sicario</title>
  <!--[if mso]>
  <noscript><xml><o:OfficeDocumentSettings><o:PixelsPerInch>96</o:PixelsPerInch></o:OfficeDocumentSettings></xml></noscript>
  <![endif]-->
  <style>
    /* Reset */
    body, table, td, a { -webkit-text-size-adjust:100%; -ms-text-size-adjust:100%; }
    table, td { mso-table-lspace:0pt; mso-table-rspace:0pt; }
    img { -ms-interpolation-mode:bicubic; border:0; outline:none; text-decoration:none; display:block; }
    body { margin:0; padding:0; background-color:${colors.bg}; width:100% !important; }
    a { color:${colors.accent}; }

    /* Mobile */
    @media only screen and (max-width:600px) {
      .email-container { width:100% !important; min-width:100% !important; }
      .email-header,
      .email-body,
      .email-footer { padding-left:20px !important; padding-right:20px !important; }
      .email-header { padding-top:20px !important; padding-bottom:16px !important; }
      .email-body { padding-top:28px !important; padding-bottom:28px !important; }
      .cta-btn, .mobile-btn { width:100% !important; display:block !important; text-align:center !important; box-sizing:border-box !important; }
      .stat-cell { display:block !important; width:100% !important; padding:0 0 10px 0 !important; }
      h1 { font-size:20px !important; }
      .body-text { font-size:15px !important; }
      .code-block { font-size:12px !important; }
    }
  </style>
</head>
<body style="margin:0;padding:0;background-color:${colors.bg};word-spacing:normal;-webkit-font-smoothing:antialiased">

  <!-- Preview text -->
  <div style="display:none;font-size:1px;color:${colors.bg};line-height:1px;max-height:0;max-width:0;opacity:0;overflow:hidden">${previewText}&nbsp;‌&nbsp;‌&nbsp;‌&nbsp;‌&nbsp;‌&nbsp;‌&nbsp;‌&nbsp;‌&nbsp;‌&nbsp;‌&nbsp;‌&nbsp;‌</div>

  <!-- Outer wrapper -->
  <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="background-color:${colors.bg}">
    <tr>
      <td align="center" style="padding:32px 12px">

        <!-- Email container — max 560px, fluid on mobile -->
        <table class="email-container" role="presentation" cellpadding="0" cellspacing="0" border="0" width="560" style="max-width:560px;width:100%">

          <!-- HEADER -->
          <tr>
            <td class="email-header" align="center" style="background-color:${colors.surface};border:1px solid ${colors.border};border-bottom:none;border-radius:12px 12px 0 0;padding:24px 40px 20px">
              ${logoHtml()}
            </td>
          </tr>

          <!-- DIVIDER -->
          <tr>
            <td style="background-color:${colors.surface};border-left:1px solid ${colors.border};border-right:1px solid ${colors.border}">
              <div style="height:1px;background-color:${colors.borderSubtle};font-size:0;line-height:0">&nbsp;</div>
            </td>
          </tr>

          <!-- BODY -->
          <tr>
            <td class="email-body" style="background-color:${colors.surface};border-left:1px solid ${colors.border};border-right:1px solid ${colors.border};padding:32px 40px">
              ${content}
            </td>
          </tr>

          <!-- FOOTER -->
          <tr>
            <td class="email-footer" style="background-color:${colors.surface};border:1px solid ${colors.border};border-top:1px solid ${colors.borderSubtle};border-radius:0 0 12px 12px;padding:18px 40px">
              <p style="margin:0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;font-size:12px;line-height:1.7;color:${colors.textMuted};text-align:center">
                You're receiving this because you have a Sicario account.
                <br>
                <a href="https://usesicario.xyz" style="color:${colors.textMuted};text-decoration:underline">usesicario.xyz</a>
                &nbsp;·&nbsp;
                <a href="https://usesicario.xyz/privacy" style="color:${colors.textMuted};text-decoration:underline">Privacy Policy</a>
              </p>
            </td>
          </tr>

        </table>

      </td>
    </tr>
  </table>
</body>
</html>`;
}

// ── Welcome email ─────────────────────────────────────────────────────────────

export async function sendWelcomeEmail(to: string, name?: string): Promise<void> {
  const resend = getResend();
  const displayName = name ?? to.split("@")[0];

  const content = `
    <h1 style="margin:0 0 8px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;font-size:24px;font-weight:700;color:${colors.textPrimary};letter-spacing:-0.02em">
      Welcome, ${displayName}
    </h1>
    <p style="margin:0 0 24px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;font-size:15px;line-height:1.7;color:${colors.textSecondary}">
      Your Sicario account is ready. Scan your codebase for vulnerabilities, publish results to the cloud dashboard, and fix them with AI-powered auto-remediation — all without your source code ever leaving your machine.
    </p>

    <!-- CTA button -->
    <table role="presentation" cellpadding="0" cellspacing="0" border="0" style="margin:0 0 32px">
      <tr>
        <td class="mobile-btn" style="border-radius:7px;background-color:${colors.accent}">
          <a href="https://usesicario.xyz/dashboard" style="display:inline-block;padding:13px 28px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;font-size:14px;font-weight:700;color:#000000;text-decoration:none;letter-spacing:0.01em">
            Go to Dashboard →
          </a>
        </td>
      </tr>
    </table>

    <!-- Divider -->
    <div style="height:1px;background-color:${colors.borderSubtle};margin:0 0 28px;font-size:0;line-height:0">&nbsp;</div>

    <!-- Quick start -->
    <p style="margin:0 0 12px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;font-size:13px;font-weight:600;color:${colors.textMuted};letter-spacing:0.06em;text-transform:uppercase">
      Get started in 30 seconds
    </p>

    <!-- Code block 1 -->
    <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="margin:0 0 8px;border-radius:7px;background-color:${colors.codeBg};border:1px solid ${colors.border}">
      <tr>
        <td style="padding:14px 18px">
          <code style="font-family:'Courier New',Courier,monospace;font-size:13px;color:${colors.codeText}">curl -fsSL https://usesicario.xyz/install.sh | sh</code>
        </td>
      </tr>
    </table>

    <!-- Code block 2 -->
    <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="margin:0 0 28px;border-radius:7px;background-color:${colors.codeBg};border:1px solid ${colors.border}">
      <tr>
        <td style="padding:14px 18px">
          <code style="font-family:'Courier New',Courier,monospace;font-size:13px;color:${colors.codeText}">sicario scan . --publish</code>
        </td>
      </tr>
    </table>

    <!-- Feature pills -->
    <table role="presentation" cellpadding="0" cellspacing="0" border="0">
      <tr>
        <td style="padding-right:8px;padding-bottom:8px">
          <span style="display:inline-block;padding:5px 12px;border-radius:20px;border:1px solid ${colors.border};font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;font-size:12px;color:${colors.textSecondary}">500+ rules</span>
        </td>
        <td style="padding-right:8px;padding-bottom:8px">
          <span style="display:inline-block;padding:5px 12px;border-radius:20px;border:1px solid ${colors.border};font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;font-size:12px;color:${colors.textSecondary}">AI auto-fix</span>
        </td>
        <td style="padding-right:8px;padding-bottom:8px">
          <span style="display:inline-block;padding:5px 12px;border-radius:20px;border:1px solid ${colors.border};font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;font-size:12px;color:${colors.textSecondary}">Zero exfiltration</span>
        </td>
      </tr>
    </table>`;

  await resend.emails.send({
    from: FROM,
    to,
    subject: "Welcome to Sicario",
    html: emailShell(content, `Your Sicario account is ready, ${displayName}.`),
  });
}

// ── Password reset OTP email ──────────────────────────────────────────────────

export async function sendPasswordResetEmail(
  to: string,
  otp: string
): Promise<void> {
  const resend = getResend();

  const content = `
    <h1 style="margin:0 0 8px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;font-size:24px;font-weight:700;color:${colors.textPrimary};letter-spacing:-0.02em">
      Reset your password
    </h1>
    <p style="margin:0 0 28px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;font-size:15px;line-height:1.7;color:${colors.textSecondary}">
      We received a request to reset the password for your Sicario account. Use the code below — it expires in <strong style="color:${colors.textPrimary}">1 hour</strong>.
    </p>

    <!-- OTP block -->
    <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="margin:0 0 28px">
      <tr>
        <td align="center" style="background-color:${colors.codeBg};border:1px solid ${colors.border};border-radius:10px;padding:28px 20px">
          <p style="margin:0 0 6px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;font-size:11px;font-weight:600;letter-spacing:0.1em;text-transform:uppercase;color:${colors.textMuted}">
            Your reset code
          </p>
          <span style="font-family:'Courier New',Courier,monospace;font-size:38px;font-weight:700;letter-spacing:0.2em;color:${colors.accent}">${otp}</span>
        </td>
      </tr>
    </table>

    <!-- Divider -->
    <div style="height:1px;background-color:${colors.borderSubtle};margin:0 0 24px;font-size:0;line-height:0">&nbsp;</div>

    <!-- Security notice -->
    <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="margin:0 0 4px">
      <tr>
        <td style="padding:14px 16px;background-color:#0f1a00;border:1px solid #2a3d00;border-radius:7px">
          <p style="margin:0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;font-size:13px;line-height:1.6;color:#8aad3a">
            <strong style="color:${colors.accent}">Didn't request this?</strong>
            &nbsp;You can safely ignore this email. Your password will not change and this code will expire automatically.
          </p>
        </td>
      </tr>
    </table>`;

  await resend.emails.send({
    from: FROM,
    to,
    subject: "Reset your Sicario password",
    html: emailShell(content, "Your password reset code is inside."),
  });
}

// ── Invitation email ──────────────────────────────────────────────────────────

export async function sendInvitationEmail(
  to: string,
  orgName: string,
  role: string,
  inviterName: string
): Promise<void> {
  const resend = getResend();

  const content = `
    <h1 style="margin:0 0 8px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;font-size:24px;font-weight:700;color:${colors.textPrimary};letter-spacing:-0.02em">
      You've been invited
    </h1>
    <p style="margin:0 0 24px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;font-size:15px;line-height:1.7;color:${colors.textSecondary}">
      <strong style="color:${colors.textPrimary}">${inviterName}</strong> has invited you to join <strong style="color:${colors.textPrimary}">${orgName}</strong> on Sicario as a <strong style="color:${colors.textPrimary}">${role}</strong>.
    </p>

    <!-- CTA button -->
    <table role="presentation" cellpadding="0" cellspacing="0" border="0" style="margin:0 0 28px">
      <tr>
        <td class="mobile-btn" style="border-radius:7px;background-color:${colors.accent}">
          <a href="https://usesicario.xyz/auth?redirect=/dashboard" style="display:inline-block;padding:13px 28px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;font-size:14px;font-weight:700;color:#000000;text-decoration:none;letter-spacing:0.01em">
            Accept Invitation →
          </a>
        </td>
      </tr>
    </table>

    <p style="margin:0 0 20px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;font-size:13px;line-height:1.6;color:${colors.textSecondary}">
      Make sure to sign in or sign up using this email address to automatically join the organization.
    </p>

    <!-- Divider -->
    <div style="height:1px;background-color:${colors.borderSubtle};margin:0 0 20px;font-size:0;line-height:0">&nbsp;</div>

    <!-- Security note -->
    <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%">
      <tr>
        <td style="padding:14px 16px;background-color:#0f1a00;border:1px solid #2a3d00;border-radius:7px">
          <p style="margin:0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;font-size:13px;line-height:1.6;color:#8aad3a">
            If you weren't expecting this invitation, you can safely ignore it.
          </p>
        </td>
      </tr>
    </table>`;

  await resend.emails.send({
    from: FROM,
    to,
    subject: `You've been invited to ${orgName} on Sicario`,
    html: emailShell(content, `${inviterName} invited you to join ${orgName}`),
  });
}

// ── Invitation accepted email ─────────────────────────────────────────────────

export async function sendInvitationAcceptedEmail(
  to: string,
  newMemberEmail: string,
  orgName: string,
  role: string
): Promise<void> {
  const resend = getResend();

  const content = `
    <h1 style="margin:0 0 8px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;font-size:24px;font-weight:700;color:${colors.textPrimary};letter-spacing:-0.02em">
      New member joined
    </h1>
    <p style="margin:0 0 28px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;font-size:15px;line-height:1.7;color:${colors.textSecondary}">
      <strong style="color:${colors.textPrimary}">${newMemberEmail}</strong> accepted their invitation and joined <strong style="color:${colors.textPrimary}">${orgName}</strong> as a <strong style="color:${colors.textPrimary}">${role}</strong>.
    </p>

    <!-- CTA button -->
    <table role="presentation" cellpadding="0" cellspacing="0" border="0" style="margin:0 0 8px">
      <tr>
        <td class="mobile-btn" style="border-radius:7px;background-color:${colors.accent}">
          <a href="https://usesicario.xyz/dashboard/settings?tab=members" style="display:inline-block;padding:13px 28px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;font-size:14px;font-weight:700;color:#000000;text-decoration:none;letter-spacing:0.01em">
            View Members →
          </a>
        </td>
      </tr>
    </table>`;

  await resend.emails.send({
    from: FROM,
    to,
    subject: `${newMemberEmail} joined ${orgName}`,
    html: emailShell(content, `A new member has joined your organization`),
  });
}

// ── Critical findings alert email ─────────────────────────────────────────────

export async function sendCriticalFindingsAlertEmail(
  to: string,
  projectName: string,
  scanId: string,
  criticalCount: number,
  highCount: number,
  totalCount: number,
  repositoryUrl: string
): Promise<void> {
  const resend = getResend();

  const content = `
    <h1 style="margin:0 0 8px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;font-size:24px;font-weight:700;color:${colors.textPrimary};letter-spacing:-0.02em">
      Security findings detected
    </h1>
    <p style="margin:0 0 24px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;font-size:15px;line-height:1.7;color:${colors.textSecondary}">
      A scan of <strong style="color:${colors.textPrimary}">${projectName}</strong> detected findings that require immediate attention.
    </p>

    <!-- Stats row -->
    <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="margin:0 0 28px">
      <tr>
        <td style="padding:0 6px 0 0" width="33%">
          <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%">
            <tr>
              <td style="background-color:${colors.codeBg};border:1px solid #4a1010;border-radius:8px;padding:16px 12px;text-align:center">
                <p style="margin:0 0 4px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;font-size:11px;font-weight:600;letter-spacing:0.08em;text-transform:uppercase;color:#f87171">Critical</p>
                <span style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;font-size:28px;font-weight:800;color:#f87171">${criticalCount}</span>
              </td>
            </tr>
          </table>
        </td>
        <td style="padding:0 6px" width="33%">
          <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%">
            <tr>
              <td style="background-color:${colors.codeBg};border:1px solid #4a2e10;border-radius:8px;padding:16px 12px;text-align:center">
                <p style="margin:0 0 4px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;font-size:11px;font-weight:600;letter-spacing:0.08em;text-transform:uppercase;color:#fb923c">High</p>
                <span style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;font-size:28px;font-weight:800;color:#fb923c">${highCount}</span>
              </td>
            </tr>
          </table>
        </td>
        <td style="padding:0 0 0 6px" width="33%">
          <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%">
            <tr>
              <td style="background-color:${colors.codeBg};border:1px solid ${colors.border};border-radius:8px;padding:16px 12px;text-align:center">
                <p style="margin:0 0 4px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;font-size:11px;font-weight:600;letter-spacing:0.08em;text-transform:uppercase;color:${colors.textMuted}">Total</p>
                <span style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;font-size:28px;font-weight:800;color:${colors.textPrimary}">${totalCount}</span>
              </td>
            </tr>
          </table>
        </td>
      </tr>
    </table>

    <!-- CTA button -->
    <table role="presentation" cellpadding="0" cellspacing="0" border="0" style="margin:0 0 24px">
      <tr>
        <td class="mobile-btn" style="border-radius:7px;background-color:${colors.accent}">
          <a href="https://usesicario.xyz/dashboard/findings" style="display:inline-block;padding:13px 28px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;font-size:14px;font-weight:700;color:#000000;text-decoration:none;letter-spacing:0.01em">
            View Findings →
          </a>
        </td>
      </tr>
    </table>

    <!-- Repo URL -->
    <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="margin:0 0 24px;border-radius:7px;background-color:${colors.codeBg};border:1px solid ${colors.border}">
      <tr>
        <td style="padding:12px 16px">
          <code style="font-family:'Courier New',Courier,monospace;font-size:12px;color:${colors.textSecondary}">${repositoryUrl}</code>
        </td>
      </tr>
    </table>

    <!-- Divider -->
    <div style="height:1px;background-color:${colors.borderSubtle};margin:0 0 16px;font-size:0;line-height:0">&nbsp;</div>

    <p style="margin:0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;font-size:12px;line-height:1.6;color:${colors.textMuted}">
      You're receiving this because you're an admin or manager of this project.
    </p>`;

  await resend.emails.send({
    from: FROM,
    to,
    subject: `[Sicario Alert] ${criticalCount} critical finding${criticalCount !== 1 ? "s" : ""} in ${projectName}`,
    html: emailShell(content, `New critical security findings detected in ${projectName}`),
  });
}

// ── Weekly digest email ───────────────────────────────────────────────────────

export async function sendWeeklyDigestEmail(
  to: string,
  orgName: string,
  stats: {
    newFindings: number;
    criticalOpen: number;
    highOpen: number;
    fixed: number;
    scansRun: number;
    topProject: string | null;
  }
): Promise<void> {
  const resend = getResend();

  const now = new Date();
  const weekAgo = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
  const dateRange = `${weekAgo.toLocaleDateString("en-US", { month: "short", day: "numeric" })} – ${now.toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" })}`;

  const criticalColor = stats.criticalOpen > 0 ? "#f87171" : colors.textPrimary;
  const highColor = stats.highOpen > 0 ? "#fb923c" : colors.textPrimary;
  const fixedColor = "#4ade80";

  const content = `
    <h1 style="margin:0 0 4px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;font-size:24px;font-weight:700;color:${colors.textPrimary};letter-spacing:-0.02em">
      Weekly Security Digest
    </h1>
    <p style="margin:0 0 28px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;font-size:14px;line-height:1.6;color:${colors.textMuted}">
      ${orgName} &nbsp;·&nbsp; ${dateRange}
    </p>

    <!-- Stats grid -->
    <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="margin:0 0 28px">
      <tr>
        <td style="padding:0 6px 12px 0" width="50%">
          <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%">
            <tr>
              <td style="background-color:${colors.codeBg};border:1px solid ${colors.border};border-radius:8px;padding:16px">
                <p style="margin:0 0 4px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;font-size:11px;font-weight:600;letter-spacing:0.08em;text-transform:uppercase;color:${colors.textMuted}">New Findings</p>
                <span style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;font-size:28px;font-weight:800;color:${colors.textPrimary}">${stats.newFindings}</span>
              </td>
            </tr>
          </table>
        </td>
        <td style="padding:0 0 12px 6px" width="50%">
          <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%">
            <tr>
              <td style="background-color:${colors.codeBg};border:1px solid ${stats.criticalOpen > 0 ? "#4a1010" : colors.border};border-radius:8px;padding:16px">
                <p style="margin:0 0 4px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;font-size:11px;font-weight:600;letter-spacing:0.08em;text-transform:uppercase;color:${criticalColor}">Critical Open</p>
                <span style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;font-size:28px;font-weight:800;color:${criticalColor}">${stats.criticalOpen}</span>
              </td>
            </tr>
          </table>
        </td>
      </tr>
      <tr>
        <td style="padding:0 6px 12px 0" width="50%">
          <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%">
            <tr>
              <td style="background-color:${colors.codeBg};border:1px solid ${stats.highOpen > 0 ? "#4a2e10" : colors.border};border-radius:8px;padding:16px">
                <p style="margin:0 0 4px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;font-size:11px;font-weight:600;letter-spacing:0.08em;text-transform:uppercase;color:${highColor}">High Open</p>
                <span style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;font-size:28px;font-weight:800;color:${highColor}">${stats.highOpen}</span>
              </td>
            </tr>
          </table>
        </td>
        <td style="padding:0 0 12px 6px" width="50%">
          <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%">
            <tr>
              <td style="background-color:${colors.codeBg};border:1px solid #1a3d1a;border-radius:8px;padding:16px">
                <p style="margin:0 0 4px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;font-size:11px;font-weight:600;letter-spacing:0.08em;text-transform:uppercase;color:${fixedColor}">Fixed This Week</p>
                <span style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;font-size:28px;font-weight:800;color:${fixedColor}">${stats.fixed}</span>
              </td>
            </tr>
          </table>
        </td>
      </tr>
      <tr>
        <td style="padding:0 6px 0 0" width="50%">
          <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%">
            <tr>
              <td style="background-color:${colors.codeBg};border:1px solid ${colors.border};border-radius:8px;padding:16px">
                <p style="margin:0 0 4px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;font-size:11px;font-weight:600;letter-spacing:0.08em;text-transform:uppercase;color:${colors.textMuted}">Scans Run</p>
                <span style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;font-size:28px;font-weight:800;color:${colors.textPrimary}">${stats.scansRun}</span>
              </td>
            </tr>
          </table>
        </td>
        <td width="50%"></td>
      </tr>
    </table>

    ${stats.topProject ? `
    <p style="margin:0 0 24px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;font-size:14px;line-height:1.6;color:${colors.textSecondary}">
      Most active project: <strong style="color:${colors.textPrimary}">${stats.topProject}</strong>
    </p>` : ""}

    <!-- CTA button -->
    <table role="presentation" cellpadding="0" cellspacing="0" border="0" style="margin:0 0 28px">
      <tr>
        <td class="mobile-btn" style="border-radius:7px;background-color:${colors.accent}">
          <a href="https://usesicario.xyz/dashboard" style="display:inline-block;padding:13px 28px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;font-size:14px;font-weight:700;color:#000000;text-decoration:none;letter-spacing:0.01em">
            View Dashboard →
          </a>
        </td>
      </tr>
    </table>

    <!-- Divider -->
    <div style="height:1px;background-color:${colors.borderSubtle};margin:0 0 16px;font-size:0;line-height:0">&nbsp;</div>

    <p style="margin:0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;font-size:12px;line-height:1.6;color:${colors.textMuted}">
      You're receiving this weekly digest as an org admin. Reply to unsubscribe.
    </p>`;

  await resend.emails.send({
    from: FROM,
    to,
    subject: `Your Sicario weekly digest — ${orgName}`,
    html: emailShell(content, `${stats.newFindings} new findings this week`),
  });
}

// ── Plan upgrade email ────────────────────────────────────────────────────────

export async function sendPlanUpgradeEmail(
  to: string,
  orgName: string,
  newPlan: string,
  billingCycle: string
): Promise<void> {
  const resend = getResend();

  const planFeatures: Record<string, string[]> = {
    pro: ["10 projects", "5,000 findings/mo", "AI auto-remediation", "Priority support"],
    team: ["Unlimited projects", "Unlimited findings", "AI auto-remediation", "Team collaboration", "Priority support"],
    enterprise: ["Unlimited projects", "Unlimited findings", "AI auto-remediation", "SSO / SAML", "Custom retention", "Dedicated CSM"],
  };

  const features = planFeatures[newPlan.toLowerCase()] ?? ["All plan features now active"];
  const featureRows = features
    .map(
      (f) =>
        `<tr><td style="padding:6px 0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;font-size:14px;color:${colors.textSecondary}"><span style="color:${colors.accent};margin-right:8px">✓</span>${f}</td></tr>`
    )
    .join("");

  const content = `
    <h1 style="margin:0 0 8px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;font-size:24px;font-weight:700;color:${colors.textPrimary};letter-spacing:-0.02em">
      Plan upgraded
    </h1>
    <p style="margin:0 0 24px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;font-size:15px;line-height:1.7;color:${colors.textSecondary}">
      Your organization <strong style="color:${colors.textPrimary}">${orgName}</strong> has been upgraded to the <strong style="color:${colors.accent}">${newPlan}</strong> plan (${billingCycle} billing). Your new limits are now active.
    </p>

    <!-- Feature list -->
    <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="margin:0 0 28px;background-color:${colors.codeBg};border:1px solid ${colors.border};border-radius:8px;padding:4px 16px">
      <tr><td>
        <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%">
          ${featureRows}
        </table>
      </td></tr>
    </table>

    <!-- CTA button -->
    <table role="presentation" cellpadding="0" cellspacing="0" border="0" style="margin:0 0 28px">
      <tr>
        <td class="mobile-btn" style="border-radius:7px;background-color:${colors.accent}">
          <a href="https://usesicario.xyz/dashboard" style="display:inline-block;padding:13px 28px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;font-size:14px;font-weight:700;color:#000000;text-decoration:none;letter-spacing:0.01em">
            Go to Dashboard →
          </a>
        </td>
      </tr>
    </table>

    <!-- Divider -->
    <div style="height:1px;background-color:${colors.borderSubtle};margin:0 0 16px;font-size:0;line-height:0">&nbsp;</div>

    <p style="margin:0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;font-size:13px;line-height:1.6;color:${colors.textMuted}">
      Questions? Reply to this email or contact <a href="mailto:support@usesicario.xyz" style="color:${colors.textMuted};text-decoration:underline">support@usesicario.xyz</a>
    </p>`;

  await resend.emails.send({
    from: FROM,
    to,
    subject: `You're now on the ${newPlan} plan — Sicario`,
    html: emailShell(content, `Your Sicario plan has been upgraded`),
  });
}

// ── Inactivity nudge email ────────────────────────────────────────────────────

export async function sendInactivityNudgeEmail(
  to: string,
  name: string,
  daysSinceLastScan: number
): Promise<void> {
  const resend = getResend();

  const content = `
    <h1 style="margin:0 0 8px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;font-size:24px;font-weight:700;color:${colors.textPrimary};letter-spacing:-0.02em">
      Time for a security check
    </h1>
    <p style="margin:0 0 24px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;font-size:15px;line-height:1.7;color:${colors.textSecondary}">
      Hi <strong style="color:${colors.textPrimary}">${name}</strong>, it's been <strong style="color:${colors.textPrimary}">${daysSinceLastScan} days</strong> since your last Sicario scan. New vulnerabilities are discovered every day — a quick scan takes under 30 seconds.
    </p>

    <!-- Scan command -->
    <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="margin:0 0 28px;border-radius:7px;background-color:${colors.codeBg};border:1px solid ${colors.border}">
      <tr>
        <td style="padding:14px 18px">
          <code style="font-family:'Courier New',Courier,monospace;font-size:13px;color:${colors.codeText}">sicario scan . --publish</code>
        </td>
      </tr>
    </table>

    <!-- CTA button -->
    <table role="presentation" cellpadding="0" cellspacing="0" border="0" style="margin:0 0 28px">
      <tr>
        <td class="mobile-btn" style="border-radius:7px;background-color:${colors.accent}">
          <a href="https://usesicario.xyz/dashboard" style="display:inline-block;padding:13px 28px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;font-size:14px;font-weight:700;color:#000000;text-decoration:none;letter-spacing:0.01em">
            View Dashboard →
          </a>
        </td>
      </tr>
    </table>

    <!-- Divider -->
    <div style="height:1px;background-color:${colors.borderSubtle};margin:0 0 16px;font-size:0;line-height:0">&nbsp;</div>

    <p style="margin:0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;font-size:12px;line-height:1.6;color:${colors.textMuted}">
      Reply to unsubscribe from these reminders.
    </p>`;

  await resend.emails.send({
    from: FROM,
    to,
    subject: `Your codebase hasn't been scanned in ${daysSinceLastScan} days`,
    html: emailShell(content, `Run a scan to check for new vulnerabilities`),
  });
}

// ── First Scan Nudge email (Task 38.2) ────────────────────────────────────────
// Sent 24h after signup if no scan has been completed yet.

export async function sendFirstScanNudgeEmail(
  to: string,
  name: string
): Promise<void> {
  const resend = getResend();
  const displayName = name || to.split("@")[0];

  const content = `
    <h1 style="margin:0 0 8px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;font-size:24px;font-weight:700;color:${colors.textPrimary};letter-spacing:-0.02em">
      Run your first scan
    </h1>
    <p style="margin:0 0 24px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;font-size:15px;line-height:1.7;color:${colors.textSecondary}">
      Hi <strong style="color:${colors.textPrimary}">${displayName}</strong>, you signed up for Sicario yesterday but haven't run a scan yet. It takes under 30 seconds and you'll see exactly what's lurking in your codebase.
    </p>

    <!-- Code block -->
    <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="margin:0 0 8px;border-radius:7px;background-color:${colors.codeBg};border:1px solid ${colors.border}">
      <tr>
        <td style="padding:14px 18px">
          <code style="font-family:'Courier New',Courier,monospace;font-size:13px;color:${colors.codeText}">curl -fsSL https://usesicario.xyz/install.sh | sh</code>
        </td>
      </tr>
    </table>
    <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="margin:0 0 28px;border-radius:7px;background-color:${colors.codeBg};border:1px solid ${colors.border}">
      <tr>
        <td style="padding:14px 18px">
          <code style="font-family:'Courier New',Courier,monospace;font-size:13px;color:${colors.codeText}">sicario scan . --publish</code>
        </td>
      </tr>
    </table>

    <!-- CTA -->
    <table role="presentation" cellpadding="0" cellspacing="0" border="0" style="margin:0 0 28px">
      <tr>
        <td class="mobile-btn" style="border-radius:7px;background-color:${colors.accent}">
          <a href="https://usesicario.xyz/dashboard" style="display:inline-block;padding:13px 28px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;font-size:14px;font-weight:700;color:#000000;text-decoration:none;letter-spacing:0.01em">
            Go to Dashboard →
          </a>
        </td>
      </tr>
    </table>

    <div style="height:1px;background-color:${colors.borderSubtle};margin:0 0 16px;font-size:0;line-height:0">&nbsp;</div>
    <p style="margin:0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;font-size:12px;line-height:1.6;color:${colors.textMuted}">
      <a href="https://usesicario.xyz/unsubscribe?email=${encodeURIComponent(to)}" style="color:${colors.textMuted};text-decoration:underline">Unsubscribe</a> from onboarding emails.
    </p>`;

  await resend.emails.send({
    from: FROM,
    to,
    subject: "Still haven't scanned yet? It takes 30 seconds.",
    html: emailShell(content, "Run your first Sicario scan in under 30 seconds."),
  });
}

// ── Day-3 Re-engagement email (Task 38.3) ─────────────────────────────────────
// Sent 72h after signup if no scan and nudge already sent.

export async function sendDayThreeReengagementEmail(
  to: string,
  name: string
): Promise<void> {
  const resend = getResend();
  const displayName = name || to.split("@")[0];

  const content = `
    <h1 style="margin:0 0 8px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;font-size:24px;font-weight:700;color:${colors.textPrimary};letter-spacing:-0.02em">
      Your code is unscanned
    </h1>
    <p style="margin:0 0 24px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;font-size:15px;line-height:1.7;color:${colors.textSecondary}">
      Hi <strong style="color:${colors.textPrimary}">${displayName}</strong>, it's been 3 days since you signed up and your codebase still hasn't been scanned. Most teams find at least one critical vulnerability on their first scan.
    </p>

    <!-- Zero-exfil callout -->
    <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="margin:0 0 28px">
      <tr>
        <td style="padding:16px;background-color:#0f1a00;border:1px solid #2a3d00;border-radius:8px">
          <p style="margin:0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;font-size:13px;line-height:1.6;color:#8aad3a">
            <strong style="color:${colors.accent}">Zero exfiltration.</strong> Sicario scans run entirely on your machine. Only structured finding metadata is uploaded — your source code never leaves your infrastructure.
          </p>
        </td>
      </tr>
    </table>

    <!-- Code block -->
    <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="margin:0 0 28px;border-radius:7px;background-color:${colors.codeBg};border:1px solid ${colors.border}">
      <tr>
        <td style="padding:14px 18px">
          <code style="font-family:'Courier New',Courier,monospace;font-size:13px;color:${colors.codeText}">sicario scan . --publish</code>
        </td>
      </tr>
    </table>

    <!-- CTA -->
    <table role="presentation" cellpadding="0" cellspacing="0" border="0" style="margin:0 0 28px">
      <tr>
        <td class="mobile-btn" style="border-radius:7px;background-color:${colors.accent}">
          <a href="https://usesicario.xyz/dashboard" style="display:inline-block;padding:13px 28px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;font-size:14px;font-weight:700;color:#000000;text-decoration:none;letter-spacing:0.01em">
            Scan My Code →
          </a>
        </td>
      </tr>
    </table>

    <div style="height:1px;background-color:${colors.borderSubtle};margin:0 0 16px;font-size:0;line-height:0">&nbsp;</div>
    <p style="margin:0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;font-size:12px;line-height:1.6;color:${colors.textMuted}">
      <a href="https://usesicario.xyz/unsubscribe?email=${encodeURIComponent(to)}" style="color:${colors.textMuted};text-decoration:underline">Unsubscribe</a> from onboarding emails.
    </p>`;

  await resend.emails.send({
    from: FROM,
    to,
    subject: "3 days in — your code still hasn't been scanned",
    html: emailShell(content, "Most teams find a critical vuln on their first scan."),
  });
}

// ── First Findings email (Task 38.4) ──────────────────────────────────────────
// Sent when the user's first scan completes with at least one finding.

export async function sendFirstFindingsEmail(
  to: string,
  name: string,
  findingsCount: number,
  criticalCount: number,
  highCount: number,
  projectName: string
): Promise<void> {
  const resend = getResend();
  const displayName = name || to.split("@")[0];

  const urgencyLine =
    criticalCount > 0
      ? `Including <strong style="color:#f87171">${criticalCount} critical</strong> finding${criticalCount !== 1 ? "s" : ""} that need immediate attention.`
      : highCount > 0
      ? `Including <strong style="color:#fb923c">${highCount} high-severity</strong> finding${highCount !== 1 ? "s" : ""}.`
      : "Review them in your dashboard and apply auto-fixes where available.";

  const content = `
    <h1 style="margin:0 0 8px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;font-size:24px;font-weight:700;color:${colors.textPrimary};letter-spacing:-0.02em">
      Your first scan is in
    </h1>
    <p style="margin:0 0 24px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;font-size:15px;line-height:1.7;color:${colors.textSecondary}">
      Hi <strong style="color:${colors.textPrimary}">${displayName}</strong>, Sicario found <strong style="color:${colors.textPrimary}">${findingsCount} finding${findingsCount !== 1 ? "s" : ""}</strong> in <strong style="color:${colors.textPrimary}">${projectName}</strong>. ${urgencyLine}
    </p>

    <!-- Stats row -->
    <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="margin:0 0 28px">
      <tr>
        <td style="padding:0 6px 0 0" width="33%">
          <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%">
            <tr>
              <td style="background-color:${colors.codeBg};border:1px solid ${criticalCount > 0 ? "#4a1010" : colors.border};border-radius:8px;padding:16px 12px;text-align:center">
                <p style="margin:0 0 4px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;font-size:11px;font-weight:600;letter-spacing:0.08em;text-transform:uppercase;color:#f87171">Critical</p>
                <span style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;font-size:28px;font-weight:800;color:#f87171">${criticalCount}</span>
              </td>
            </tr>
          </table>
        </td>
        <td style="padding:0 6px" width="33%">
          <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%">
            <tr>
              <td style="background-color:${colors.codeBg};border:1px solid ${highCount > 0 ? "#4a2e10" : colors.border};border-radius:8px;padding:16px 12px;text-align:center">
                <p style="margin:0 0 4px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;font-size:11px;font-weight:600;letter-spacing:0.08em;text-transform:uppercase;color:#fb923c">High</p>
                <span style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;font-size:28px;font-weight:800;color:#fb923c">${highCount}</span>
              </td>
            </tr>
          </table>
        </td>
        <td style="padding:0 0 0 6px" width="33%">
          <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%">
            <tr>
              <td style="background-color:${colors.codeBg};border:1px solid ${colors.border};border-radius:8px;padding:16px 12px;text-align:center">
                <p style="margin:0 0 4px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;font-size:11px;font-weight:600;letter-spacing:0.08em;text-transform:uppercase;color:${colors.textMuted}">Total</p>
                <span style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;font-size:28px;font-weight:800;color:${colors.textPrimary}">${findingsCount}</span>
              </td>
            </tr>
          </table>
        </td>
      </tr>
    </table>

    <!-- CTA -->
    <table role="presentation" cellpadding="0" cellspacing="0" border="0" style="margin:0 0 28px">
      <tr>
        <td class="mobile-btn" style="border-radius:7px;background-color:${colors.accent}">
          <a href="https://usesicario.xyz/dashboard/findings" style="display:inline-block;padding:13px 28px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;font-size:14px;font-weight:700;color:#000000;text-decoration:none;letter-spacing:0.01em">
            View Findings →
          </a>
        </td>
      </tr>
    </table>

    <!-- Auto-fix callout -->
    <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="margin:0 0 8px">
      <tr>
        <td style="padding:14px 16px;background-color:#0f1a00;border:1px solid #2a3d00;border-radius:7px">
          <p style="margin:0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;font-size:13px;line-height:1.6;color:#8aad3a">
            <strong style="color:${colors.accent}">Auto-fix available.</strong> Run <code style="font-family:'Courier New',Courier,monospace;font-size:12px">sicario fix .</code> to apply deterministic patches — zero tokens burned, zero code exfiltrated.
          </p>
        </td>
      </tr>
    </table>`;

  await resend.emails.send({
    from: FROM,
    to,
    subject: `Sicario found ${findingsCount} finding${findingsCount !== 1 ? "s" : ""} in ${projectName}`,
    html: emailShell(content, `${findingsCount} security findings detected in your first scan.`),
  });
}

// ── Test email action (dev/staging only) ─────────────────────────────────────
// Call from the Convex dashboard or CLI:
//   npx convex run emails:sendTestEmail '{"to":"you@example.com","type":"welcome"}'

export const sendTestEmail = action({
  args: {
    to: v.string(),
    type: v.optional(
      v.union(
        v.literal("welcome"),
        v.literal("password_reset"),
        v.literal("invitation"),
        v.literal("critical_findings"),
        v.literal("weekly_digest")
      )
    ),
  },
  handler: async (_ctx, args) => {
    const emailType = args.type ?? "welcome";

    switch (emailType) {
      case "welcome":
        await sendWelcomeEmail(args.to, "Test User");
        break;

      case "password_reset":
        await sendPasswordResetEmail(args.to, "123456");
        break;

      case "invitation":
        await sendInvitationEmail(
          args.to,
          "Acme Corp",
          "developer",
          "Alice (alice@acme.com)"
        );
        break;

      case "critical_findings":
        await sendCriticalFindingsAlertEmail(
          args.to,
          "my-app",
          "scan_test_001",
          3,
          7,
          14,
          "https://github.com/acme/my-app"
        );
        break;

      case "weekly_digest":
        await sendWeeklyDigestEmail(args.to, "Acme Corp", {
          newFindings: 12,
          criticalOpen: 2,
          highOpen: 5,
          fixed: 8,
          scansRun: 4,
          topProject: "my-app",
        });
        break;

      default:
        throw new Error(`Unknown email type: ${emailType}`);
    }

    return { ok: true, type: emailType, to: args.to };
  },
});
