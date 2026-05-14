// SAFE: href-javascript — URL validated to only allow http/https schemes
// Rule: ReactHrefJavascript | CWE-79 | Expected: TrueNegative

import React from 'react';

interface SafeLinkProps {
  href: string;
  children: React.ReactNode;
}

function isSafeUrl(url: string): boolean {
  // SAFE: only allow http and https schemes; reject javascript:, data:, vbscript:, etc.
  try {
    const parsed = new URL(url);
    return parsed.protocol === 'http:' || parsed.protocol === 'https:';
  } catch {
    // Relative URLs are safe
    return url.startsWith('/') || url.startsWith('./') || url.startsWith('../');
  }
}

const SafeLink: React.FC<SafeLinkProps> = ({ href, children }) => {
  if (!isSafeUrl(href)) {
    return <span>{children}</span>;
  }
  return (
    <a href={href} rel="noopener noreferrer">
      {children}
    </a>
  );
};

export default SafeLink;
