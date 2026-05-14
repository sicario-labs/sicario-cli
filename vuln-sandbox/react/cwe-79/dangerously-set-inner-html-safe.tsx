// SAFE: dangerously-set-inner-html — DOMPurify sanitizes HTML before rendering
// Rule: ReactDangerouslySetInnerHTML | CWE-79 | Expected: TrueNegative

import React from 'react';
import DOMPurify from 'dompurify';

interface RichTextProps {
  htmlContent: string;
}

const RichText: React.FC<RichTextProps> = ({ htmlContent }) => {
  // SAFE: DOMPurify strips dangerous tags and attributes before setting innerHTML
  const sanitized = DOMPurify.sanitize(htmlContent, {
    ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'p', 'br'],
    ALLOWED_ATTR: [],
  });

  return <div dangerouslySetInnerHTML={{ __html: sanitized }} />;
};

// Alternative safe approach: use textContent via React's default rendering
const SafeText: React.FC<{ text: string }> = ({ text }) => {
  // SAFE: React escapes text content by default; no dangerouslySetInnerHTML needed
  return <p>{text}</p>;
};

export { RichText, SafeText };
