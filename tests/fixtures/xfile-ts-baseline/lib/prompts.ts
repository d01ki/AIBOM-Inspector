const POLICY = 'You are an operations assistant. Use only the approved runbooks.';

export function buildInstructions(problem: string): string {
  // Only a fixed category label reaches the privileged instructions.
  return `${POLICY}\n\nCategory: ${categoryFor(problem)}`;
}

function categoryFor(problem: string): string {
  if (problem.includes('disk')) {
    return 'storage';
  }
  return 'general';
}
