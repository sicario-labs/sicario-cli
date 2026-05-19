import React from 'react';
import { AbsoluteFill, useCurrentFrame } from 'remotion';
import { THEME, FONTS } from '../style';
import Terminal from '../components/Terminal';
import { ANSI } from '../components/TerminalColors';
import { fadeIn } from '../utils';
import type { TermLine } from '../components/Terminal';

const sbomLines: TermLine[] = [
  { segments: [{ text: '$ sicario audit --ci' }], startFrame: 5, perChar: 4 },
  { segments: [{ text: '' }], startFrame: 25 },
  {
    segments: [
      { text: '  ', fg: ANSI.brightBlack },
      { text: '📦', fg: ANSI.white },
      { text: '  Running CI pipeline checks...', fg: ANSI.brightBlack },
    ],
    startFrame: 30,
    perChar: 2,
  },
  { segments: [{ text: '' }], startFrame: 45 },
  {
    segments: [
      { text: '  ✓ ', fg: ANSI.green, bold: true },
      { text: 'SBOM generated (SPDX 2.3)', fg: ANSI.white },
    ],
    startFrame: 50,
  },
  {
    segments: [
      { text: '  ✓ ', fg: ANSI.green, bold: true },
      { text: '0 critical vulnerabilities across 286 files', fg: ANSI.green },
    ],
    startFrame: 58,
  },
  {
    segments: [
      { text: '  ✓ ', fg: ANSI.green, bold: true },
      { text: 'Policy gate: all secrets externalized', fg: ANSI.white },
    ],
    startFrame: 66,
  },
  {
    segments: [
      { text: '  ✓ ', fg: ANSI.green, bold: true },
      { text: 'Compliance: ', fg: ANSI.white },
      { text: 'SOC 2', fg: ANSI.green },
      { text: ' • ', fg: ANSI.brightBlack },
      { text: 'HIPAA', fg: ANSI.green },
      { text: ' • ', fg: ANSI.brightBlack },
      { text: 'GDPR', fg: ANSI.green },
    ],
    startFrame: 74,
    perChar: 2,
  },
  { segments: [{ text: '' }], startFrame: 90 },
  {
    segments: [
      { text: '  ', fg: ANSI.brightBlack },
      { text: '📋', fg: ANSI.white },
      { text: '  Audit Report — PR #12,847', fg: ANSI.white, bold: true },
    ],
    startFrame: 94,
  },
  {
    segments: [
      { text: '  ', fg: ANSI.brightBlack },
      { text: '─────────────────────────────────────────────────────', fg: ANSI.brightBlack, dim: true },
    ],
    startFrame: 102,
  },
  {
    segments: [
      { text: '  ✓ ', fg: ANSI.green },
      { text: 'No hardcoded secrets in PR', fg: ANSI.white },
    ],
    startFrame: 108,
  },
  {
    segments: [
      { text: '  ✓ ', fg: ANSI.green },
      { text: 'All dependencies pass SCA', fg: ANSI.white },
    ],
    startFrame: 116,
  },
  {
    segments: [
      { text: '  ✓ ', fg: ANSI.green },
      { text: 'Crypto uses approved algorithms', fg: ANSI.white },
    ],
    startFrame: 124,
  },
  {
    segments: [
      { text: '  ✓ ', fg: ANSI.green },
      { text: 'Audit log: secure & tamper-proof', fg: ANSI.white },
    ],
    startFrame: 132,
  },
  { segments: [{ text: '' }], startFrame: 140 },
  {
    segments: [
      { text: '  ', fg: ANSI.green, bold: true },
      { text: '✔ All gates passed. Ready to merge.', fg: ANSI.green },
    ],
    startFrame: 144,
    perChar: 2,
  },
];

const Enterprise: React.FC = () => {
  const frame = useCurrentFrame();

  return (
    <AbsoluteFill
      style={{
        backgroundColor: THEME.bg,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: 40,
      }}
    >
      <div
        style={{
          position: 'absolute',
          inset: 0,
          background: `radial-gradient(ellipse at 70% 50%, rgba(173,255,47,0.04) 0%, transparent 60%)`,
        }}
      />

      <div
        style={{
          textAlign: 'center',
          marginBottom: 24,
          position: 'relative',
          zIndex: 1,
          opacity: fadeIn(frame, 20, 5),
        }}
      >
        <span
          style={{
            fontFamily: FONTS.sans,
            fontSize: 36,
            fontWeight: 700,
            color: THEME.text,
          }}
        >
          Enterprise Pipeline Integration
        </span>
        <div style={{ marginTop: 6, opacity: fadeIn(frame, 15, 30) }}>
          <span
            style={{
              fontFamily: FONTS.sans,
              fontSize: 16,
              fontWeight: 300,
              color: THEME.textSecondary,
            }}
          >
            One platform from commit to deploy. SBOM, policy, compliance — automated.
          </span>
        </div>
      </div>

      <div style={{ width: 780, position: 'relative', zIndex: 1 }}>
        <Terminal lines={sbomLines} title="sicario audit --ci" width={780} />
      </div>

      <div
        style={{
          marginTop: 20,
          display: 'flex',
          gap: 16,
          position: 'relative',
          zIndex: 1,
          opacity: fadeIn(frame, 20, 180),
        }}
      >
        {[
          { label: 'SBOM Generation', color: THEME.accent },
          { label: 'Policy Gates', color: THEME.accent },
          { label: 'Compliance Auto', color: THEME.accent },
          { label: 'CI/CD Native', color: THEME.accent },
        ].map((tag) => (
          <div
            key={tag.label}
            style={{
              padding: '5px 12px',
              backgroundColor: THEME.bgTertiary,
              border: `1px solid ${THEME.border}`,
              borderRadius: 20,
              fontFamily: FONTS.sans,
              fontSize: 12,
              color: tag.color,
            }}
          >
            {tag.label}
          </div>
        ))}
      </div>
    </AbsoluteFill>
  );
};

export default Enterprise;
