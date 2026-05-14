// SAFE: open-redirect — redirect target validated against an allowlist
// Rule: ReactWindowLocation | CWE-601 | Expected: TrueNegative

import React from 'react';

const ALLOWED_PATHS = ['/dashboard', '/profile', '/settings', '/home'];

interface RedirectButtonProps {
  target: string;
  label: string;
}

const RedirectButton: React.FC<RedirectButtonProps> = ({ target, label }) => {
  const handleClick = () => {
    // SAFE: only redirect to known internal paths; reject external URLs
    if (ALLOWED_PATHS.includes(target)) {
      window.location.href = target;
    } else {
      console.warn('Redirect to disallowed target blocked:', target);
      window.location.href = '/home';
    }
  };

  return <button onClick={handleClick}>{label}</button>;
};

export default RedirectButton;
