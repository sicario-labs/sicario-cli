import React from 'react';
import { useCurrentFrame, interpolate, spring, useVideoConfig } from 'remotion';
import { THEME, FONTS } from '../style';

interface PulseLogoProps {
  size?: number;
  showText?: boolean;
  delay?: number;
  textSize?: number;
}

const PulseLogo: React.FC<PulseLogoProps> = ({
  size = 48,
  showText = true,
  delay = 0,
  textSize,
}) => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();

  const scale = interpolate(frame - delay, [0, 20], [0, 1], {
    extrapolateRight: 'clamp',
    extrapolateLeft: 'clamp',
  });

  const glowOpacity = interpolate(
    Math.sin((frame - delay) * 0.04),
    [-1, 1],
    [0.3, 0.8],
    { extrapolateRight: 'clamp', extrapolateLeft: 'clamp' }
  );

  return (
    <div
      style={{
        display: 'flex',
        alignItems: 'center',
        gap: 12,
        opacity: Math.min(1, Math.max(0, frame - delay) / 15),
        transform: `scale(${Math.min(1, scale)})`,
      }}
    >
      <div style={{ position: 'relative' }}>
        <div
          style={{
            position: 'absolute',
            inset: -6,
            borderRadius: '50%',
            backgroundColor: THEME.accentGlow,
            opacity: glowOpacity,
            filter: 'blur(10px)',
          }}
        />
        <div
          style={{
            width: size,
            height: size,
            backgroundColor: THEME.accent,
            borderRadius: '50%',
            position: 'relative',
            overflow: 'hidden',
            flexShrink: 0,
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
      {showText && (
        <span
          style={{
            color: THEME.text,
            fontFamily: FONTS.sans,
            fontSize: textSize ?? size * 0.6,
            fontWeight: 700,
            letterSpacing: '-0.02em',
            textTransform: 'uppercase',
          }}
        >
          sicario
        </span>
      )}
    </div>
  );
};

export default PulseLogo;
