import { interpolate, spring, useVideoConfig } from 'remotion';
import { THEME } from '../style';

export const ANSI = {
  black: '#0a0a0a',
  red: '#ff4444',
  green: THEME.accent,
  yellow: '#fbbf24',
  blue: '#58a6ff',
  magenta: '#d2a8ff',
  cyan: '#39d2c0',
  white: '#e5e5e5',
  brightBlack: '#525252',
  brightRed: '#ff6b6b',
  brightGreen: '#b8ff5c',
  brightYellow: '#fcd34d',
  brightBlue: '#79c0ff',
  brightMagenta: '#dbb8ff',
  brightCyan: '#56d4c8',
  brightWhite: '#ffffff',
};

export const TERM_THEME = {
  bg: '#0a0a0a',
  fg: '#e5e5e5',
  cursor: THEME.accent,
  selection: 'rgba(173, 255, 47, 0.2)',
  border: THEME.border,
  chromeBg: '#111111',
};

export const FONT_SIZES = {
  normal: 15,
  small: 12,
  heading: 13,
};
