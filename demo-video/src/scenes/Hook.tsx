import React from 'react';
import { AbsoluteFill, useCurrentFrame, interpolate } from 'remotion';
import { THEME, FONTS } from '../style';
import PulseLogo from '../components/PulseLogo';
import { fadeIn, typewriterChars } from '../utils';

const Hook: React.FC = () => {
  const frame = useCurrentFrame();

  const bgGlow = interpolate(
    Math.sin(frame * 0.03),
    [-1, 1],
    [0, 0.05],
    { extrapolateRight: 'clamp', extrapolateLeft: 'clamp' }
  );

  const line1 = typewriterChars(frame, 'Every line of code is a potential breach.', 15, 3);
  const line1Opacity = fadeIn(frame, 20, 15);

  const line2 = typewriterChars(frame, '29,000,000,000 records exposed last year alone.', 120, 3);
  const line2Opacity = fadeIn(frame, 20, 120);

  const line3 = typewriterChars(frame, 'The question is —', 240, 3);
  const line3Opacity = fadeIn(frame, 20, 240);

  const line4 = typewriterChars(frame, 'will you find yours before the attackers do?', 290, 3);
  const line4Opacity = fadeIn(frame, 20, 290);

  const logoVisible = frame > 360;
  const revealText = typewriterChars(frame, 'Sicario: 581 rules. Zero exfiltration.', 375, 3);

  return (
    <AbsoluteFill
      style={{
        backgroundColor: THEME.bg,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: 60,
      }}
    >
      <div
        style={{
          position: 'absolute',
          inset: 0,
          background: `radial-gradient(ellipse at 50% 40%, ${THEME.error}${Math.round(bgGlow * 255).toString(16).padStart(2, '0')} 0%, transparent 60%)`,
        }}
      />

      <div
        style={{
          position: 'absolute',
          inset: 0,
          backgroundImage: `
            linear-gradient(rgba(255,255,255,0.02) 1px, transparent 1px),
            linear-gradient(90deg, rgba(255,255,255,0.02) 1px, transparent 1px)
          `,
          backgroundSize: '40px 40px',
          opacity: 0.5,
        }}
      />

      <div style={{ textAlign: 'center', position: 'relative', zIndex: 1, maxWidth: 900 }}>
        <div style={{ opacity: line1Opacity, marginBottom: 24 }}>
          <span
            style={{
              fontFamily: FONTS.sans,
              fontSize: 52,
              fontWeight: 700,
              color: THEME.text,
              letterSpacing: '-0.02em',
            }}
          >
            {line1}
          </span>
        </div>

        <div style={{ opacity: line2Opacity, marginBottom: 24 }}>
          <span
            style={{
              fontFamily: FONTS.sans,
              fontSize: 42,
              fontWeight: 300,
              color: THEME.textSecondary,
            }}
          >
            {line2}
          </span>
        </div>

        {frame > 220 && (
          <div style={{ opacity: line3Opacity, marginBottom: 8 }}>
            <span
              style={{
                fontFamily: FONTS.sans,
                fontSize: 36,
                fontWeight: 600,
                color: THEME.text,
              }}
            >
              {line3}
            </span>
          </div>
        )}

        {frame > 270 && (
          <div style={{ opacity: line4Opacity, marginBottom: 48 }}>
            <span
              style={{
                fontFamily: FONTS.sans,
                fontSize: 36,
                fontWeight: 600,
                color: THEME.accent,
              }}
            >
              {line4}
            </span>
          </div>
        )}

        {frame > 355 && (
          <div
            style={{
              opacity: fadeIn(frame, 20, 360),
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
              gap: 20,
            }}
          >
            <span
              style={{
                fontFamily: FONTS.sans,
                fontSize: 22,
                fontWeight: 400,
                color: THEME.accent,
              }}
            >
              {revealText}
            </span>
            <PulseLogo size={36} delay={380} />
          </div>
        )}
      </div>
    </AbsoluteFill>
  );
};

export default Hook;
