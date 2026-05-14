// SAFE: command-injection — allowlist validation prevents command injection
// Rule: InjectChildProcessShellTrue | CWE-78 | Expected: TrueNegative

const express = require('express');
const { spawn } = require('child_process');

const app = express();

const ALLOWED_COMMANDS = ['ls', 'pwd', 'date'];

app.get('/run', (req, res) => {
  const command = req.query.cmd;

  // SAFE: command validated against an allowlist; shell:false (default) prevents metacharacter injection
  if (!ALLOWED_COMMANDS.includes(command)) {
    return res.status(400).json({ error: 'Command not allowed' });
  }

  const proc = spawn(command, [], { shell: false });
  let output = '';
  proc.stdout.on('data', (data) => { output += data.toString(); });
  proc.on('close', () => res.json({ output }));
});

app.listen(3000);
