// SAFE: dom-document-write — React state used to render content instead of document.write
// Rule: DomDocumentWrite | CWE-79 | Expected: TrueNegative

import React, { useState } from 'react';

const ContentRenderer: React.FC = () => {
  const [content, setContent] = useState('');
  const [displayContent, setDisplayContent] = useState('');

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    // SAFE: content rendered via React state; React escapes text by default
    // document.write() is never called
    setDisplayContent(content);
  };

  return (
    <div>
      <form onSubmit={handleSubmit}>
        <input
          value={content}
          onChange={(e) => setContent(e.target.value)}
          placeholder="Enter content"
        />
        <button type="submit">Display</button>
      </form>
      {/* SAFE: React renders displayContent as text, not HTML */}
      {displayContent && <p>{displayContent}</p>}
    </div>
  );
};

export default ContentRenderer;
