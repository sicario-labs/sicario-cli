// SAFE: cors-wildcard — specific origin used instead of wildcard in CORS configuration
// Rule: WebCorsWildcard | CWE-942 | Expected: TrueNegative

// This file demonstrates the safe server-side CORS configuration pattern.
// The React component itself makes a credentialed fetch to a properly configured API.

import React, { useEffect, useState } from 'react';

// Safe server-side Express CORS configuration (for documentation):
// app.use(cors({
//   origin: 'https://app.example.com',  // SAFE: specific origin, not '*'
//   credentials: true,
//   methods: ['GET', 'POST'],
// }));

const DataFetcher: React.FC = () => {
  const [data, setData] = useState<string>('');

  useEffect(() => {
    // SAFE: fetch with credentials to a server that uses a specific CORS origin
    fetch('https://api.example.com/data', { credentials: 'include' })
      .then((r) => r.json())
      .then((d) => setData(JSON.stringify(d)))
      .catch(console.error);
  }, []);

  return <div>Data: {data}</div>;
};

export default DataFetcher;
