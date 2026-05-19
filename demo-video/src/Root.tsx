import React from 'react';
import { Composition } from 'remotion';
import SicarioDemo from './SicarioDemo';
import { DURATION_FRAMES, FPS, THEME } from './style';

const Root: React.FC = () => {
  return (
    <>
      <Composition
        id="SicarioDemo"
        component={SicarioDemo}
        durationInFrames={DURATION_FRAMES}
        fps={FPS}
        width={1920}
        height={1080}
        defaultProps={{}}
      />
    </>
  );
};

export default Root;
