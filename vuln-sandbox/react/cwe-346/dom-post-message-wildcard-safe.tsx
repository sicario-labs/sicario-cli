// SAFE: dom-post-message-wildcard — specific target origin used instead of wildcard
// Rule: DomPostMessageWildcard | CWE-346 | Expected: TrueNegative

import React, { useEffect } from 'react';

const TRUSTED_ORIGIN = 'https://parent.example.com';

const EmbeddedWidget: React.FC = () => {
  useEffect(() => {
    const handleMessage = (event: MessageEvent) => {
      // SAFE: validate the origin before processing the message
      if (event.origin !== TRUSTED_ORIGIN) {
        console.warn('Message from untrusted origin rejected:', event.origin);
        return;
      }
      console.log('Received trusted message:', event.data);
    };

    window.addEventListener('message', handleMessage);
    return () => window.removeEventListener('message', handleMessage);
  }, []);

  const sendMessage = () => {
    // SAFE: specific target origin used instead of '*'
    window.parent.postMessage({ type: 'ready', payload: 'widget loaded' }, TRUSTED_ORIGIN);
  };

  return <button onClick={sendMessage}>Notify Parent</button>;
};

export default EmbeddedWidget;
