// VULNERABLE: InjectChildProcessShellTrue — spawn with shell:true (TypeScript)
// Rule: InjectChildProcessShellTrue | CWE-78 | Severity: CRITICAL

import express, { Request, Response } from 'express';
import { spawn } from 'child_process';

const app = express();
app.use(express.json());

interface RunRequest {
  command: string;
  args?: string[];
}

app.post('/run', (req: Request<{}, {}, RunRequest>, res: Response): void => {
  const { command, args = [] } = req.body;

  // VULNERABLE: shell:true allows shell metacharacter injection
  // An attacker can pass: "ls" with args ["; cat /etc/passwd"] to read sensitive files
  const proc = spawn(command, args, { shell: true });

  let output = '';
  proc.stdout.on('data', (data: Buffer) => { output += data.toString(); });
  proc.stderr.on('data', (data: Buffer) => { output += data.toString(); });
  proc.on('close', (code: number | null) => {
    res.json({ output, exitCode: code });
  });
});

app.listen(3000);
