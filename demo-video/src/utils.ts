import { interpolate } from 'remotion';

export const fadeIn = (frame: number, duration: number = 15, delay: number = 0): number =>
  interpolate(frame, [delay, delay + duration], [0, 1], {
    extrapolateRight: 'clamp',
    extrapolateLeft: 'clamp',
  });

export const fadeOut = (frame: number, start: number, duration: number = 15): number =>
  interpolate(frame, [start, start + duration], [1, 0], {
    extrapolateRight: 'clamp',
    extrapolateLeft: 'clamp',
  });

export const slideIn = (
  frame: number,
  delay: number = 0,
  duration: number = 20,
  from: number = 30
): number =>
  interpolate(frame, [delay, delay + duration], [from, 0], {
    extrapolateRight: 'clamp',
    extrapolateLeft: 'clamp',
  });

export const scaleIn = (
  frame: number,
  delay: number = 0,
  duration: number = 20
): number =>
  interpolate(frame, [delay, delay + duration], [0.8, 1], {
    extrapolateRight: 'clamp',
    extrapolateLeft: 'clamp',
  });

export const typewriterChars = (
  frame: number,
  text: string,
  startFrame: number,
  perChar: number = 2
): string =>
  text.slice(0, Math.max(0, Math.floor((frame - startFrame) / perChar)));

export const clamp = (value: number, min: number, max: number): number =>
  Math.min(max, Math.max(min, value));
