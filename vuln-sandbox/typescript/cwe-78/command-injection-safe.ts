// SAFE: command-injection — allowlist validation and shell:false prevent injection (TypeScript)
// Rule: InjectChildProcessShellTrue | CWE-78 | Expected: TrueNegative

import express, { Request, Response } from 'express';
import { spawn } from 'child_process';

const app = express();
app.use(express.json());

const ALLOWED_COMMANDS: ReadonlySet<string> = new Set(['ls', 'pwd', 'date', 'uptime']);

app.get('/run', (req: Request, res: Response): void => {
  const command = req.query.cmd as string;

  // SAFE: command validated against allowlist; shell:false (default) prevents metacharacter injection
  if (!ALLOWED_COMMANDS.has(command)) {
    res.status(400).json({ error: 'Command not allowed' });
    return;
  }

  const proc = spawn(command, [], { shell: false });
  let output = '';
  proc.stdout.on('data', (data: Buffer) => { output += data.toString(); });
  proc.on('close', () => res.json({ output }));
});

app.listen(3000);
