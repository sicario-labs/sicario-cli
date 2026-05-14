// SAFE: eval-injection — JSON.parse used instead of eval() to parse data
// Rule: InjectEval | CWE-95 | Expected: TrueNegative

import React, { useState } from 'react';

const Calculator: React.FC = () => {
  const [input, setInput] = useState('');
  const [result, setResult] = useState<number | null>(null);
  const [error, setError] = useState('');

  const calculate = () => {
    // SAFE: parse structured JSON input instead of evaluating arbitrary expressions
    try {
      const parsed = JSON.parse(input) as { a: number; b: number; op: string };
      const ops: Record<string, (a: number, b: number) => number> = {
        add: (a, b) => a + b,
        sub: (a, b) => a - b,
        mul: (a, b) => a * b,
        div: (a, b) => b !== 0 ? a / b : NaN,
      };
      if (!ops[parsed.op]) { setError('Unknown operation'); return; }
      setResult(ops[parsed.op](parsed.a, parsed.b));
      setError('');
    } catch {
      setError('Invalid JSON input');
    }
  };

  return (
    <div>
      <input value={input} onChange={(e) => setInput(e.target.value)} placeholder='{"a":1,"b":2,"op":"add"}' />
      <button onClick={calculate}>Calculate</button>
      {result !== null && <p>Result: {result}</p>}
      {error && <p style={{ color: 'red' }}>{error}</p>}
    </div>
  );
};

export default Calculator;
