import React from 'react';
import { AbsoluteFill, useCurrentFrame, interpolate } from 'remotion';
import { THEME, FONTS } from '../style';
import Terminal from '../components/Terminal';
import { ANSI } from '../components/TerminalColors';
import { fadeIn } from '../utils';
import type { TermLine } from '../components/Terminal';

const scanLines: TermLine[] = [
  { segments: [{ text: '$ sicario scan --path ~/project' }], startFrame: 5, perChar: 4 },
  { segments: [{ text: '' }], startFrame: 40 },
  {
    segments: [
      { text: '  ', fg: ANSI.brightBlack },
      { text: '🔍', fg: ANSI.white },
      { text: '  Scanning 286 files with 581 tree-sitter rules...', fg: ANSI.brightBlack },
    ],
    startFrame: 45,
    perChar: 2,
  },
  {
    segments: [
      { text: '  ', fg: ANSI.brightBlack },
      { text: '📁', fg: ANSI.white },
      { text: '  Repository: vuln-sandbox (git, 2.4MB)', fg: ANSI.brightBlack },
    ],
    startFrame: 55,
    perChar: 2,
  },
  { segments: [{ text: '' }], startFrame: 63 },
  {
    segments: [
      { text: ' ✓ ', fg: ANSI.green, bold: true },
      { text: 'src/auth.ts', fg: ANSI.white },
      { text: '                   ', fg: ANSI.white },
      { text: '3 rules matched', fg: ANSI.brightBlack },
    ],
    startFrame: 68,
  },
  {
    segments: [
      { text: ' ⚠ ', fg: ANSI.yellow, bold: true },
      { text: 'src/config.ts', fg: ANSI.white },
      { text: '                 ', fg: ANSI.white },
      { text: 'Hardcoded API key detected', fg: ANSI.yellow },
    ],
    startFrame: 76,
  },
  {
    segments: [
      { text: ' ✗ ', fg: ANSI.red, bold: true },
      { text: '.env.production', fg: ANSI.white },
      { text: '                ', fg: ANSI.white },
      { text: 'Database URL exposed', fg: ANSI.red },
    ],
    startFrame: 84,
  },
  {
    segments: [
      { text: ' ✓ ', fg: ANSI.green, bold: true },
      { text: 'src/routes/api.ts', fg: ANSI.white },
      { text: '                ', fg: ANSI.white },
      { text: '0 rules', fg: ANSI.brightBlack },
    ],
    startFrame: 92,
  },
  {
    segments: [
      { text: ' ✓ ', fg: ANSI.green, bold: true },
      { text: 'src/utils/crypto.ts', fg: ANSI.white },
      { text: '              ', fg: ANSI.white },
      { text: '0 rules', fg: ANSI.brightBlack },
    ],
    startFrame: 100,
  },
  {
    segments: [
      { text: ' ✗ ', fg: ANSI.red, bold: true },
      { text: 'src/keys.pem', fg: ANSI.white },
      { text: '                  ', fg: ANSI.white },
      { text: 'Private key detected', fg: ANSI.red },
    ],
    startFrame: 108,
  },
  {
    segments: [
      { text: ' ✓ ', fg: ANSI.green, bold: true },
      { text: 'src/lib/validator.ts', fg: ANSI.white },
      { text: '             ', fg: ANSI.white },
      { text: '0 rules', fg: ANSI.brightBlack },
    ],
    startFrame: 116,
  },
  {
    segments: [
      { text: ' ⚠ ', fg: ANSI.yellow, bold: true },
      { text: 'docker-compose.yml', fg: ANSI.white },
      { text: '              ', fg: ANSI.white },
      { text: 'Hardcoded credentials', fg: ANSI.yellow },
    ],
    startFrame: 124,
  },
  { segments: [{ text: '' }], startFrame: 130 },
  {
    segments: [
      { text: '  ', fg: ANSI.brightBlack },
      { text: '─────────────────────────────────────────────────────', fg: ANSI.brightBlack, dim: true },
    ],
    startFrame: 134,
  },
  { segments: [{ text: '' }], startFrame: 140 },
  {
    segments: [
      { text: '  Results:  ', fg: ANSI.white, bold: true },
      { text: '801 findings', fg: ANSI.white },
      { text: ' (', fg: ANSI.white },
      { text: '2 critical', fg: ANSI.red, bold: true },
      { text: ', ', fg: ANSI.white },
      { text: '342 high', fg: ANSI.yellow },
      { text: ', ', fg: ANSI.white },
      { text: '457 medium/low', fg: ANSI.brightBlack },
      { text: ')', fg: ANSI.white },
    ],
    startFrame: 146,
    perChar: 2,
  },
  {
    segments: [
      { text: '  Rules:    ', fg: ANSI.white, bold: true },
      { text: '581 tree-sitter rules', fg: ANSI.green },
    ],
    startFrame: 180,
    perChar: 2,
  },
  {
    segments: [
      { text: '  Files:    ', fg: ANSI.white, bold: true },
      { text: '286 files scanned', fg: ANSI.white },
    ],
    startFrame: 210,
    perChar: 2,
  },
  {
    segments: [
      { text: '  Time:     ', fg: ANSI.white, bold: true },
      { text: '1.84s', fg: ANSI.cyan },
      { text: ' (29 files/s, 2.9 KLOC/s)', fg: ANSI.brightBlack },
    ],
    startFrame: 240,
    perChar: 2,
  },
  {
    segments: [
      { text: '  Network:  ', fg: ANSI.white, bold: true },
      { text: '🚫 Zero exfiltration', fg: ANSI.green },
      { text: ' (all scans local)', fg: ANSI.brightBlack },
    ],
    startFrame: 290,
    perChar: 2,
  },
];

const CountUp: React.FC<{ target: number; startFrame: number; duration: number }> = ({
  target,
  startFrame,
  duration,
}) => {
  const frame = useCurrentFrame();
  const value = interpolate(frame, [startFrame, startFrame + duration], [0, target], {
    extrapolateRight: 'clamp',
    extrapolateLeft: 'clamp',
  });
  return <>{Math.floor(value)}</>;
};

const Scan: React.FC = () => {
  const frame = useCurrentFrame();
  const statsVisible = frame > 340;

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
          top: 0,
          left: 0,
          right: 0,
          height: 4,
          backgroundColor: THEME.bgTertiary,
        }}
      >
        <div
          style={{
            height: '100%',
            width: `${interpolate(frame, [0, 320], [0, 100], { extrapolateRight: 'clamp' })}%`,
            backgroundColor: THEME.accent,
            boxShadow: `0 0 20px ${THEME.accentDim}`,
          }}
        />
      </div>

      <div style={{ width: 840 }}>
        <Terminal lines={scanLines} title="sicario scan — vuln-sandbox" width={840} />
      </div>

      {statsVisible && (
        <div
          style={{
            marginTop: 28,
            display: 'flex',
            gap: 64,
            opacity: fadeIn(frame, 20, 340),
          }}
        >
          {[
            { value: 581, label: 'Tree-Sitter Rules', color: THEME.accent },
            { value: 286, label: 'Files Scanned', color: THEME.text },
            { value: 801, label: 'Findings', color: THEME.warning },
            { value: 1.84, label: 'Seconds', color: THEME.cyan },
          ].map((stat) => (
            <div key={stat.label} style={{ textAlign: 'center' }}>
              <div
                style={{
                  fontFamily: FONTS.mono,
                  fontSize: 42,
                  fontWeight: 700,
                  color: stat.color,
                }}
              >
                {stat.value < 10 ? (
                  <CountUp target={Math.round(stat.value * 100)} startFrame={360} duration={30} />
                ) : (
                  <CountUp target={stat.value} startFrame={360} duration={30} />
                )}
              </div>
              <div
                style={{
                  fontFamily: FONTS.sans,
                  fontSize: 11,
                  color: THEME.textDim,
                  textTransform: 'uppercase',
                  letterSpacing: '0.1em',
                  marginTop: 6,
                }}
              >
                {stat.label}
              </div>
            </div>
          ))}
        </div>
      )}
    </AbsoluteFill>
  );
};

export default Scan;
