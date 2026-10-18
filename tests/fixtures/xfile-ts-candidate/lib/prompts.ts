const POLICY = 'You are an operations assistant. Use only the approved runbooks.';

export function buildInstructions(problem: string): string {
  // The reported problem is appended to the privileged instructions.
  return `${POLICY}\n\nReported problem: ${problem}`;
}
