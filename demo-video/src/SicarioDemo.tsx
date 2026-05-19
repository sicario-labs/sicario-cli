import React from 'react';
import { AbsoluteFill, Sequence, Audio, staticFile } from 'remotion';
import Hook from './scenes/Hook';
import Scan from './scenes/Scan';
import AutoFix from './scenes/AutoFix';
import Enterprise from './scenes/Enterprise';
import Ask from './scenes/Ask';
import { ScanLines, Vignette } from './components/Transition';
import { SCENE } from './style';

const SicarioDemo: React.FC = () => {
  return (
    <AbsoluteFill>
      <Audio src={staticFile('audio/bgm.mp3')} volume={0.5} />

      <Sequence from={SCENE.HOOK.start} durationInFrames={SCENE.HOOK.end - SCENE.HOOK.start}>
        <Audio src={staticFile('audio/hook.mp3')} />
        <Hook />
      </Sequence>

      <Sequence from={SCENE.SCAN.start} durationInFrames={SCENE.SCAN.end - SCENE.SCAN.start}>
        <Audio src={staticFile('audio/scan.mp3')} />
        <Scan />
      </Sequence>

      <Sequence from={SCENE.AUTOFIX.start} durationInFrames={SCENE.AUTOFIX.end - SCENE.AUTOFIX.start}>
        <Audio src={staticFile('audio/autofix.mp3')} />
        <AutoFix />
      </Sequence>

      <Sequence from={SCENE.ENTERPRISE.start} durationInFrames={SCENE.ENTERPRISE.end - SCENE.ENTERPRISE.start}>
        <Audio src={staticFile('audio/enterprise.mp3')} />
        <Enterprise />
      </Sequence>

      <Sequence from={SCENE.ASK.start} durationInFrames={SCENE.ASK.end - SCENE.ASK.start}>
        <Audio src={staticFile('audio/ask.mp3')} />
        <Ask />
      </Sequence>

      <ScanLines />
      <Vignette />
    </AbsoluteFill>
  );
};

export default SicarioDemo;
