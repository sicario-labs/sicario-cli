import { Resend } from "resend";
const r = new Resend("re_fKs7kJ72_6VDjvCZ3cbvubgGgWU4kwzes");
const result = await r.emails.send({
  from: "Emmanuel from Sicario <noreply@usesicario.xyz>",
  to: "emmycodes234@gmail.com",
  subject: "Reset your Sicario password",
  html: `<div style="background:#0a0a0a;padding:40px;font-family:-apple-system,sans-serif">
    <table cellpadding="0" cellspacing="0" border="0"><tr>
      <td style="padding-right:10px">
        <svg width="28" height="28" viewBox="0 0 28 28" fill="none" xmlns="http://www.w3.org/2000/svg">
          <circle cx="14" cy="14" r="14" fill="#ADFF2F"/>
          <line x1="20" y1="7" x2="8" y2="21" stroke="#000" stroke-width="3" stroke-linecap="round"/>
        </svg>
      </td>
      <td><span style="font-size:18px;font-weight:800;color:#fff;letter-spacing:0.08em;text-transform:uppercase">SICARIO</span></td>
    </tr></table>
    <hr style="border:none;border-top:1px solid #1f1f1f;margin:24px 0">
    <h1 style="color:#f4f4f5;font-size:24px;font-weight:700;margin:0 0 8px">Reset your password</h1>
    <p style="color:#a1a1aa;font-size:15px;line-height:1.7;margin:0 0 28px">
      We received a request to reset the password for your Sicario account.
      Use the code below — it expires in <strong style="color:#f4f4f5">1 hour</strong>.
    </p>
    <div style="background:#111;border:1px solid #1f1f1f;border-radius:10px;padding:28px;text-align:center;margin:0 0 28px">
      <p style="margin:0 0 6px;font-size:11px;font-weight:600;letter-spacing:0.1em;text-transform:uppercase;color:#52525b">Your reset code</p>
      <span style="font-family:'Courier New',monospace;font-size:38px;font-weight:700;letter-spacing:0.2em;color:#ADFF2F">123456</span>
    </div>
    <div style="background:#0f1a00;border:1px solid #2a3d00;border-radius:7px;padding:14px 16px">
      <p style="margin:0;font-size:13px;line-height:1.6;color:#8aad3a">
        <strong style="color:#ADFF2F">Didn't request this?</strong>
        You can safely ignore this email. Your password will not change.
      </p>
    </div>
    <hr style="border:none;border-top:1px solid #181818;margin:24px 0">
    <p style="margin:0;font-size:12px;color:#52525b">
      You're receiving this because you have a Sicario account.
      &nbsp;·&nbsp;<a href="https://usesicario.xyz" style="color:#52525b">usesicario.xyz</a>
    </p>
  </div>`,
});
if (result.error) {
  console.error("FAILED:", result.error.message);
} else {
  console.log("✓ Sent password reset email  (id:", result.data?.id + ")");
}
