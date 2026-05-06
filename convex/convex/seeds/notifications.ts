/**
 * Seed: Initial Notifications
 *
 * This file documents the one-time seed data for the `notifications` table.
 * Run this via the Convex dashboard or by calling the `notifications.create`
 * mutation directly from the Convex CLI:
 *
 *   npx convex run notifications:create '{
 *     "notificationId": "v2-beta-launch",
 *     "message": "Sicario v2 Beta is live — 10 new features including Ollama air-gapped fixes and Ghost Fix hooks.",
 *     "severity": "info",
 *     "minVersion": "0.9.0",
 *     "url": "https://usesicario.xyz/changelog",
 *     "activeFrom": "2025-06-01T00:00:00.000Z",
 *     "enabled": true
 *   }'
 *
 * Alternatively, paste the JSON below into the Convex dashboard under
 * Data → notifications → Add Document.
 *
 * ── Verification ─────────────────────────────────────────────────────────────
 *
 * After seeding:
 *
 * 1. First run — notification should appear:
 *    $ sicario scan
 *    (scan output)
 *
 *    ℹ  Sicario v2 Beta is live — 10 new features including Ollama air-gapped fixes and Ghost Fix hooks.
 *       → https://usesicario.xyz/changelog
 *
 * 2. Second run — notification should NOT appear (seen_notifications.json updated):
 *    $ sicario scan
 *    (scan output only, no notification)
 *
 * The seen_notifications.json file is stored at ~/.sicario/seen_notifications.json.
 * To reset and see the notification again, remove the "v2-beta-launch" entry from
 * that file (or delete the file entirely).
 */

/**
 * v2 Beta Launch Notification
 *
 * Shown to all users running sicario >= 0.9.0 from the v2 release date onwards.
 * No expiry (activeTo is null) — the notification remains active indefinitely
 * until manually disabled via `notifications.disable`.
 */
export const V2_BETA_LAUNCH_NOTIFICATION = {
  notificationId: "v2-beta-launch",
  message:
    "Sicario v2 Beta is live — 10 new features including Ollama air-gapped fixes and Ghost Fix hooks.",
  severity: "info" as const,
  minVersion: "0.9.0",
  maxVersion: undefined, // no upper bound
  url: "https://usesicario.xyz/changelog",
  activeFrom: "2025-06-01T00:00:00.000Z", // v2 release date
  activeTo: undefined, // never expires
  enabled: true,
};
