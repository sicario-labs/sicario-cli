// SAFE: local-storage-token — auth token stored in httpOnly cookie, not localStorage
// Rule: ReactLocalStorageToken | CWE-922 | Expected: TrueNegative

import React, { useState } from 'react';

// SAFE: token is stored server-side in an httpOnly cookie (set via Set-Cookie header),
// not in localStorage or sessionStorage where JavaScript can access it.
// The login function calls the API which sets the cookie; no token is stored client-side.

const LoginForm: React.FC = () => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    const response = await fetch('/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      // SAFE: credentials: 'include' allows the server to set an httpOnly cookie
      credentials: 'include',
      body: JSON.stringify({ username, password }),
    });

    if (!response.ok) {
      setError('Invalid credentials');
      return;
    }

    // SAFE: no token stored in localStorage; the httpOnly cookie is managed by the browser
    window.location.href = '/dashboard';
  };

  return (
    <form onSubmit={handleLogin}>
      <input value={username} onChange={(e) => setUsername(e.target.value)} placeholder="Username" />
      <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} placeholder="Password" />
      <button type="submit">Login</button>
      {error && <p style={{ color: 'red' }}>{error}</p>}
    </form>
  );
};

export default LoginForm;
