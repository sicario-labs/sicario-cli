// SAFE: use-effect-missing-dep — all dependencies included in the dependency array
// Rule: ReactUseEffectMissingDep | CWE-362 | Expected: TrueNegative

import React, { useState, useEffect, useCallback } from 'react';

interface User {
  id: number;
  name: string;
}

const UserProfile: React.FC<{ userId: number }> = ({ userId }) => {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(false);

  const fetchUser = useCallback(async (id: number) => {
    setLoading(true);
    const response = await fetch(`/api/users/${id}`);
    const data: User = await response.json();
    setUser(data);
    setLoading(false);
  }, []);

  // SAFE: userId and fetchUser are both listed in the dependency array
  useEffect(() => {
    fetchUser(userId);
  }, [userId, fetchUser]);

  if (loading) return <p>Loading...</p>;
  if (!user) return <p>No user found</p>;
  return <p>Hello, {user.name}!</p>;
};

export default UserProfile;
