import React, { useMemo } from 'react';
import { useCurrentFrame, interpolate } from 'remotion';
import { THEME, FONTS } from '../style';
import { TERM_THEME, FONT_SIZES } from './TerminalColors';

export interface StyledSegment {
  text: string;
  fg?: string;
  bold?: boolean;
  dim?: boolean;
}

export interface TermLine {
  segments: StyledSegment[];
  startFrame: number;
  perChar?: number;
  indent?: number;
  isContinuation?: boolean;
}

interface TerminalProps {
  lines: TermLine[];
  title?: string;
  width?: number;
  height?: number;
  lineHeight?: number;
}

const CHAR_W = 9.2;
const CHAR_H = 21;

const Cursor: React.FC<{ frame: number; offset: number }> = ({ frame, offset }) => {
  const visible = Math.sin((frame + offset) * 0.12) > 0;
  return (
    <span
      style={{
        display: 'inline-block',
        width: CHAR_W - 1,
        height: CHAR_H - 3,
        backgroundColor: visible ? TERM_THEME.cursor : 'transparent',
        verticalAlign: 'text-top',
        marginLeft: 0,
      }}
    />
  );
};

const LineRow: React.FC<{ line: TermLine; frame: number }> = ({ line, frame }) => {
  const { segments, startFrame, perChar = 2, indent = 0, isContinuation } = line;
  const elapsed = frame - startFrame;
  if (elapsed < 0) return null;

  const totalChars = segments.reduce((n, s) => n + s.text.length, 0);
  const charsVisible = Math.min(totalChars, Math.floor(elapsed / perChar));
  const fullyVisible = charsVisible >= totalChars;

  const opacity = interpolate(elapsed, [0, 8], [0, 1], {
    extrapolateRight: 'clamp',
    extrapolateLeft: 'clamp',
  });

  const charsUsed = segments.reduce(
    (acc, seg) => {
      if (acc.remaining <= 0) return acc;
      const take = Math.min(seg.text.length, acc.remaining);
      const visible = seg.text.slice(0, take);
      acc.remaining -= take;
      acc.parts.push({ ...seg, text: visible });
      return acc;
    },
    { remaining: charsVisible, parts: [] as StyledSegment[] }
  );

  const cursorVisible = !fullyVisible && charsVisible < totalChars;

  return (
    <div
      style={{
        display: 'flex',
        opacity,
        transform: `translateY(${interpolate(elapsed, [0, 12], [6, 0], { extrapolateRight: 'clamp', extrapolateLeft: 'clamp' })}px)`,
        minHeight: CHAR_H + 2,
        alignItems: 'center',
        paddingLeft: isContinuation ? CHAR_W * 3 : 0,
      }}
    >
      {!isContinuation && (
        <span
          style={{
            width: CHAR_W * 2,
            color: THEME.textDim,
            fontFamily: FONTS.mono,
            fontSize: FONT_SIZES.normal,
            lineHeight: `${CHAR_H}px`,
            userSelect: 'none',
            textAlign: 'right',
            paddingRight: 8,
            flexShrink: 0,
          }}
        />
      )}

      <div
        style={{
          whiteSpace: 'pre',
          fontFamily: FONTS.mono,
          fontSize: FONT_SIZES.normal,
          lineHeight: `${CHAR_H}px`,
          letterSpacing: 0,
          height: CHAR_H,
        }}
      >
        {charsUsed.parts.map((seg, i) => (
          <span
            key={i}
            style={{
              color: seg.fg ?? TERM_THEME.fg,
              fontWeight: seg.bold ? 700 : 400,
              opacity: seg.dim ? 0.5 : 1,
            }}
          >
            {seg.text}
          </span>
        ))}
        {cursorVisible && <Cursor frame={frame} offset={startFrame} />}
      </div>
    </div>
  );
};

const Terminal: React.FC<TerminalProps> = ({
  lines,
  title = 'bash',
  width = 740,
  height = 'auto',
  lineHeight = CHAR_H + 4,
}) => {
  const frame = useCurrentFrame();

  const visibleLines = useMemo(
    () => lines.filter((l) => frame >= l.startFrame),
    [lines, frame]
  );

  return (
    <div
      style={{
        width,
        height,
        backgroundColor: TERM_THEME.chromeBg,
        border: `1px solid ${TERM_THEME.border}`,
        borderRadius: 12,
        overflow: 'hidden',
        boxShadow: `0 0 60px rgba(0,0,0,0.5), 0 8px 32px rgba(0,0,0,0.4)`,
      }}
    >
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          padding: '10px 16px',
          backgroundColor: TERM_THEME.chromeBg,
          borderBottom: `1px solid ${TERM_THEME.border}`,
        }}
      >
        <div style={{ display: 'flex', gap: 8 }}>
          {['#ff5f57', '#ffbd2e', '#28c840'].map((color) => (
            <div
              key={color}
              style={{
                width: 13,
                height: 13,
                borderRadius: '50%',
                backgroundColor: color,
              }}
            />
          ))}
        </div>
        <div
          style={{
            flex: 1,
            textAlign: 'center',
            paddingRight: 58,
          }}
        >
          <span
            style={{
              color: THEME.textDim,
              fontSize: 12,
              fontFamily: FONTS.sans,
            }}
          >
            {title}
          </span>
        </div>
      </div>

      <div
        style={{
          backgroundColor: TERM_THEME.bg,
          padding: '14px 16px',
          minHeight: 300,
        }}
      >
        {visibleLines.map((line, i) => (
          <LineRow key={`${line.startFrame}-${i}`} line={line} frame={frame} />
        ))}
      </div>
    </div>
  );
};

export { CHAR_H, CHAR_W };
export default Terminal;
