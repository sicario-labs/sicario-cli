import React from 'react';
import { AbsoluteFill, useCurrentFrame, interpolate, spring, useVideoConfig } from 'remotion';
import { THEME, FONTS } from '../style';
import { fadeIn, typewriterChars } from '../utils';

const Ask: React.FC = () => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();

  const logoScale = spring({
    frame: frame - 20,
    fps,
    config: { damping: 12, stiffness: 100, mass: 0.5 },
  });

  const line1 = typewriterChars(frame, "We're redefining application security.", 30, 3);
  const line1Opacity = fadeIn(frame, 20, 30);

  const line2 = typewriterChars(frame, 'Not a scanner that finds problems —', 110, 3);
  const line2Opacity = fadeIn(frame, 20, 110);

  const line3 = typewriterChars(frame, 'a platform that solves them.', 200, 3);
  const line3Opacity = fadeIn(frame, 20, 200);

  const urlOpacity = fadeIn(frame, 20, 300);
  const tagOpacity = fadeIn(frame, 15, 350);

  const glowPulse = interpolate(
    Math.sin(frame * 0.04),
    [-1, 1],
    [0.3, 0.8],
    { extrapolateRight: 'clamp', extrapolateLeft: 'clamp' }
  );

  return (
    <AbsoluteFill
      style={{
        backgroundColor: THEME.bg,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
      }}
    >
      <div
        style={{
          position: 'absolute',
          inset: 0,
          background: `radial-gradient(ellipse at 50% 40%, ${THEME.accentGlow} 0%, transparent 60%)`,
          opacity: glowPulse,
        }}
      />

      <div
        style={{
          position: 'absolute',
          inset: 0,
          backgroundImage: `
            linear-gradient(rgba(255,255,255,0.015) 1px, transparent 1px),
            linear-gradient(90deg, rgba(255,255,255,0.015) 1px, transparent 1px)
          `,
          backgroundSize: '60px 60px',
          opacity: 0.3,
        }}
      />

      <div style={{ textAlign: 'center', position: 'relative', zIndex: 1, maxWidth: 900 }}>
        <div
          style={{
            opacity: line1Opacity,
            marginBottom: 16,
          }}
        >
          <span
            style={{
              fontFamily: FONTS.sans,
              fontSize: 44,
              fontWeight: 700,
              color: THEME.text,
              letterSpacing: '-0.02em',
            }}
          >
            {line1}
          </span>
        </div>

        <div style={{ opacity: line2Opacity, marginBottom: 8 }}>
          <span
            style={{
              fontFamily: FONTS.sans,
              fontSize: 36,
              fontWeight: 300,
              color: THEME.textSecondary,
            }}
          >
            {line2}
          </span>
        </div>

        {frame > 180 && (
          <div style={{ opacity: line3Opacity, marginBottom: 40 }}>
            <span
              style={{
                fontFamily: FONTS.sans,
                fontSize: 36,
                fontWeight: 600,
                color: THEME.accent,
              }}
            >
              {line3}
            </span>
          </div>
        )}

        {frame > 280 && (
          <div
            style={{
              opacity: urlOpacity,
              marginBottom: 28,
              transform: `scale(${logoScale})`,
            }}
          >
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                gap: 16,
              }}
            >
              <div style={{ position: 'relative' }}>
                <div
                  style={{
                    position: 'absolute',
                    inset: -12,
                    borderRadius: '50%',
                    backgroundColor: THEME.accentGlow,
                    filter: 'blur(16px)',
                    opacity: glowPulse,
                  }}
                />
                <div
                  style={{
                    width: 56,
                    height: 56,
                    backgroundColor: THEME.accent,
                    borderRadius: '50%',
                    position: 'relative',
                    overflow: 'hidden',
                  }}
                >
                  <div
                    style={{
                      position: 'absolute',
                      inset: 0,
                      backgroundColor: 'rgba(0,0,0,0.2)',
                      transform: 'rotate(45deg) translateX(30%)',
                    }}
                  />
                </div>
              </div>
              <span
                style={{
                  color: THEME.text,
                  fontFamily: FONTS.sans,
                  fontSize: 48,
                  fontWeight: 700,
                  letterSpacing: '-0.02em',
                  textTransform: 'uppercase',
                }}
              >
                sicario
              </span>
            </div>
            <div style={{ marginTop: 12 }}>
              <span
                style={{
                  fontFamily: FONTS.mono,
                  fontSize: 22,
                  color: THEME.accent,
                }}
              >
                usesicario.xyz
              </span>
            </div>
          </div>
        )}

        {frame > 340 && (
          <div style={{ opacity: tagOpacity }}>
            <div
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: 8,
                padding: '6px 16px',
                backgroundColor: THEME.bgTertiary,
                border: `1px solid ${THEME.border}`,
                borderRadius: 20,
              }}
            >
              <span
                style={{
                  width: 6,
                  height: 6,
                  borderRadius: '50%',
                  backgroundColor: THEME.accent,
                  display: 'inline-block',
                }}
              />
              <span
                style={{
                  fontFamily: FONTS.sans,
                  fontSize: 12,
                  color: THEME.textDim,
                  textTransform: 'uppercase',
                  letterSpacing: '0.08em',
                }}
              >
                Selected for Canopy 2025
              </span>
            </div>
          </div>
        )}
      </div>
    </AbsoluteFill>
  );
};

export default Ask;
