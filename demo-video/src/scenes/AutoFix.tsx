import React from 'react';
import { AbsoluteFill, useCurrentFrame } from 'remotion';
import { THEME, FONTS } from '../style';
import Terminal from '../components/Terminal';
import { ANSI } from '../components/TerminalColors';
import { fadeIn } from '../utils';
import type { TermLine } from '../components/Terminal';

const fixLines: TermLine[] = [
  { segments: [{ text: '$ sicario fix --auto' }], startFrame: 5, perChar: 4 },
  { segments: [{ text: '' }], startFrame: 30 },
  {
    segments: [
      { text: '  ', fg: ANSI.brightBlack },
      { text: '🔧', fg: ANSI.white },
      { text: '  Analyzing 801 findings for auto-fix candidates...', fg: ANSI.brightBlack },
    ],
    startFrame: 35,
    perChar: 2,
  },
  { segments: [{ text: '' }], startFrame: 55 },
  {
    segments: [
      { text: '  ✓ ', fg: ANSI.green, bold: true },
      { text: 'js-xss-vue-v-html', fg: ANSI.white },
      { text: '              ', fg: ANSI.white },
      { text: 'Added HTML sanitization', fg: ANSI.brightBlack },
    ],
    startFrame: 60,
  },
  {
    segments: [
      { text: '  ✓ ', fg: ANSI.green, bold: true },
      { text: 'js-xss-ejs-unescaped', fg: ANSI.white },
      { text: '            ', fg: ANSI.white },
      { text: 'Escaped template output', fg: ANSI.brightBlack },
    ],
    startFrame: 75,
  },
  {
    segments: [
      { text: '  ✓ ', fg: ANSI.green, bold: true },
      { text: 'js-sql-template-literal', fg: ANSI.white },
      { text: '          ', fg: ANSI.white },
      { text: 'Parameterized query inserted', fg: ANSI.brightBlack },
    ],
    startFrame: 90,
  },
  { segments: [{ text: '' }], startFrame: 103 },
  {
    segments: [
      { text: '  ', fg: ANSI.brightBlack },
      { text: '📋', fg: ANSI.white },
      { text: '  Generating patches...', fg: ANSI.brightBlack },
    ],
    startFrame: 107,
    perChar: 2,
  },
  { segments: [{ text: '' }], startFrame: 125 },
  {
    segments: [
      { text: '  ──── vuln-file.js ────', fg: ANSI.brightBlack, dim: true },
    ],
    startFrame: 129,
    perChar: 2,
  },
  {
    segments: [
      { text: '  -', fg: ANSI.red, bold: true },
      { text: ' element.innerHTML = userInput', fg: ANSI.red },
    ],
    startFrame: 140,
  },
  {
    segments: [
      { text: '  +', fg: ANSI.green, bold: true },
      { text: ' element.textContent = userInput', fg: ANSI.green },
    ],
    startFrame: 152,
  },
  { segments: [{ text: '' }], startFrame: 162 },
  {
    segments: [
      { text: '  ──── db/query.js ────', fg: ANSI.brightBlack, dim: true },
    ],
    startFrame: 165,
    perChar: 2,
  },
  {
    segments: [
      { text: '  -', fg: ANSI.red, bold: true },
      { text: ' db.query(`SELECT * FROM users WHERE id = \${id}`)', fg: ANSI.red },
    ],
    startFrame: 176,
  },
  {
    segments: [
      { text: '  +', fg: ANSI.green, bold: true },
      { text: ' db.query("SELECT * FROM users WHERE id = $1", [id])', fg: ANSI.green },
    ],
    startFrame: 188,
  },
  { segments: [{ text: '' }], startFrame: 200 },
  {
    segments: [
      { text: '  ', fg: ANSI.green, bold: true },
      { text: '✔ Applied 3 auto-fixes. 0 errors. 0 tokens burned.', fg: ANSI.green },
    ],
    startFrame: 204,
    perChar: 2,
  },
  {
    segments: [
      { text: '  ', fg: ANSI.brightBlack },
      { text: 'Deterministic AST patching — verifiable, repeatable, zero exfiltration.', fg: ANSI.brightBlack },
    ],
    startFrame: 230,
    perChar: 2,
  },
];

const AutoFix: React.FC = () => {
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
          background: `radial-gradient(ellipse at 30% 50%, ${THEME.accentGlow} 0%, transparent 60%)`,
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
          Deterministic Auto-Fix
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
            AST-level patching — not AI guesswork. Zero data leaves your machine.
          </span>
        </div>
      </div>

      <div style={{ width: 800, position: 'relative', zIndex: 1 }}>
        <Terminal lines={fixLines} title="sicario fix --auto" width={800} />
      </div>

      <div
        style={{
          marginTop: 20,
          display: 'flex',
          gap: 12,
          position: 'relative',
          zIndex: 1,
          opacity: fadeIn(frame, 20, 270),
        }}
      >
        {['Hardcoded Secrets', 'SQL Injection', 'XSS', 'Zero Exfiltration'].map(
          (tag) => (
            <div
              key={tag}
              style={{
                padding: '5px 12px',
                backgroundColor: THEME.bgTertiary,
                border: `1px solid ${THEME.border}`,
                borderRadius: 20,
                fontFamily: FONTS.sans,
                fontSize: 12,
                color: THEME.accent,
              }}
            >
              ✓ {tag}
            </div>
          )
        )}
      </div>
    </AbsoluteFill>
  );
};

export default AutoFix;
