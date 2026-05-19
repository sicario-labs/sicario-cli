import React, { useMemo } from 'react';
import { useCurrentFrame } from 'remotion';
import { THEME, FONTS } from '../style';
import { fadeIn } from '../utils';
import type { DiffLine } from '../types';

interface DiffViewerProps {
  lines: DiffLine[];
  startFrame: number;
  label: string;
}

const GUTTER_WIDTH = 40;

const DiffLineRow: React.FC<{ line: DiffLine; index: number; visible: boolean }> = ({
  line,
  index,
  visible,
}) => {
  const bgColor =
    line.type === 'add'
      ? 'rgba(173, 255, 47, 0.08)'
      : line.type === 'del'
        ? 'rgba(255, 68, 68, 0.08)'
        : 'transparent';

  const textColor =
    line.type === 'add'
      ? THEME.accent
      : line.type === 'del'
        ? THEME.error
        : THEME.textSecondary;

  const prefix = line.type === 'add' ? '+' : line.type === 'del' ? '-' : ' ';

  return (
    <div
      style={{
        display: 'flex',
        fontFamily: FONTS.mono,
        fontSize: 14,
        lineHeight: 1.8,
        backgroundColor: bgColor,
        opacity: visible ? 1 : 0,
        transition: 'opacity 0.2s',
      }}
    >
      <div
        style={{
          width: GUTTER_WIDTH,
          textAlign: 'right',
          paddingRight: 12,
          color: THEME.textDim,
          userSelect: 'none',
          fontSize: 12,
        }}
      >
        {index + 1}
      </div>
      <div
        style={{
          width: 20,
          color: textColor,
          userSelect: 'none',
          fontWeight: 700,
        }}
      >
        {prefix}
      </div>
      <div style={{ flex: 1, color: textColor, whiteSpace: 'pre' }}>
        {line.content}
      </div>
    </div>
  );
};

const DiffViewer: React.FC<DiffViewerProps> = ({ lines, startFrame, label }) => {
  const frame = useCurrentFrame();

  const PER_LINE_DELAY = 2;

  return (
    <div
      style={{
        backgroundColor: THEME.bgSecondary,
        border: `1px solid ${THEME.border}`,
        borderRadius: 10,
        overflow: 'hidden',
      }}
    >
      <div
        style={{
          padding: '8px 16px',
          backgroundColor: THEME.bgTertiary,
          borderBottom: `1px solid ${THEME.border}`,
          color: THEME.textSecondary,
          fontFamily: FONTS.sans,
          fontSize: 12,
          fontWeight: 600,
          textTransform: 'uppercase',
          letterSpacing: '0.05em',
        }}
      >
        {label}
      </div>
      <div style={{ padding: '8px 0' }}>
        {lines.map((line, i) => {
          const lineVisible = fadeIn(frame, 3, startFrame + i * PER_LINE_DELAY);
          return (
            <DiffLineRow
              key={i}
              line={line}
              index={i}
              visible={lineVisible > 0.5}
            />
          );
        })}
      </div>
    </div>
  );
};

export default DiffViewer;
