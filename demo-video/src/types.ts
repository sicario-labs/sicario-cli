export interface TerminalLine {
  text: string;
  startFrame: number;
  perChar?: number;
  color?: string;
  isPrompt?: boolean;
  indent?: number;
}

export interface DiffLine {
  type: 'add' | 'del' | 'same';
  content: string;
  highlight?: boolean;
}

export interface CodeExample {
  before: string[];
  after: string[];
  label: string;
  startFrame: number;
}
