export const THEME = {
  bg: '#0a0a0a',
  bgSecondary: '#111111',
  bgTertiary: '#1a1a1a',
  accent: '#ADFF2F',
  accentDim: 'rgba(173, 255, 47, 0.3)',
  accentGlow: 'rgba(173, 255, 47, 0.15)',
  text: '#ffffff',
  textSecondary: '#a3a3a3',
  textDim: '#525252',
  error: '#ff4444',
  errorDim: 'rgba(255, 68, 68, 0.15)',
  warning: '#fbbf24',
  success: '#ADFF2F',
  cyan: '#6ee7ff',
  border: '#262626',
  borderDim: '#1a1a1a',
};

export const FPS = 30;
export const DURATION_FRAMES = 3600;

export const SCENE = {
  HOOK: { start: 0, end: 450 },
  SCAN: { start: 450, end: 1050 },
  AUTOFIX: { start: 1050, end: 1950 },
  ENTERPRISE: { start: 1950, end: 2550 },
  ASK: { start: 2550, end: 3600 },
} as const;

export const FONTS = {
  sans: `'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif`,
  mono: `'JetBrains Mono', 'Fira Code', 'Cascadia Code', monospace`,
};
