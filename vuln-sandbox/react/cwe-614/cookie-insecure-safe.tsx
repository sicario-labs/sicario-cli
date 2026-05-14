// SAFE: cookie-insecure — cookie set with Secure, HttpOnly, and SameSite flags
// Rule: WebCookieInsecure | CWE-614 | Expected: TrueNegative

// This file demonstrates the safe server-side cookie configuration pattern.
// Cookies with security flags are set via the Set-Cookie response header.

import React from 'react';

// Safe server-side cookie setting (for documentation):
// res.cookie('session', token, {
//   httpOnly: true,   // SAFE: prevents JavaScript access
//   secure: true,     // SAFE: only sent over HTTPS
//   sameSite: 'strict', // SAFE: prevents CSRF
//   maxAge: 3600000,
// });

const SecureCookieInfo: React.FC = () => {
  // SAFE: this component does not set cookies via document.cookie
  // Cookies are managed server-side with proper security flags
  return (
    <div>
      <p>Authentication is managed via secure httpOnly cookies.</p>
      <p>Cookies are set server-side with Secure, HttpOnly, and SameSite=Strict flags.</p>
    </div>
  );
};

export default SecureCookieInfo;
