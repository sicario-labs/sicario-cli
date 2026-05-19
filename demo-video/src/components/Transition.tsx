import React from 'react';
import { interpolate, useCurrentFrame } from 'remotion';
import { THEME } from '../style';

interface TransitionProps {
  frame: number;
  duration?: number;
  type?: 'wipe' | 'fade' | 'scan';
}

const ScanLines: React.FC = () => (
  <div
    style={{
      position: 'absolute',
      inset: 0,
      zIndex: 9998,
      pointerEvents: 'none',
      background: `repeating-linear-gradient(
        0deg,
        transparent,
        transparent 2px,
        rgba(0, 0, 0, 0.08) 2px,
        rgba(0, 0, 0, 0.08) 4px
      )`,
    }}
  />
);

const Vignette: React.FC = () => (
  <div
    style={{
      position: 'absolute',
      inset: 0,
      zIndex: 9997,
      pointerEvents: 'none',
      background: 'radial-gradient(ellipse at center, transparent 60%, rgba(0,0,0,0.6) 100%)',
    }}
  />
);

const Transition: React.FC<TransitionProps> = ({
  frame,
  duration = 20,
  type = 'scan',
}) => {
  const progress = interpolate(frame, [0, duration], [0, 1], {
    extrapolateRight: 'clamp',
    extrapolateLeft: 'clamp',
  });

  if (type === 'wipe') {
    return (
      <div
        style={{
          position: 'absolute',
          inset: 0,
          zIndex: 9999,
          transform: `translateX(${(1 - progress) * 100}%)`,
          backgroundColor: THEME.bg,
        }}
      />
    );
  }

  if (type === 'fade') {
    return (
      <div
        style={{
          position: 'absolute',
          inset: 0,
          zIndex: 9999,
          backgroundColor: THEME.bg,
          opacity: 1 - progress,
        }}
      />
    );
  }

  const scanY = interpolate(frame, [0, duration], [-100, 100], {
    extrapolateRight: 'clamp',
    extrapolateLeft: 'clamp',
  });

  return (
    <div
      style={{
        position: 'absolute',
        inset: 0,
        zIndex: 9999,
        background: `linear-gradient(
          180deg,
          ${THEME.accent} 0%,
          ${THEME.accent} 3px,
          transparent 3px,
          transparent 6px
        )`,
        backgroundSize: '100% 6px',
        transform: `translateY(${scanY}%)`,
        opacity: 0.3,
      }}
    />
  );
};

export { ScanLines, Vignette };
export default Transition;
