// Edge case: URL validation before fetch — should NOT trigger
export async function fetchWithValidation(url: string) {
  if (!validateUrl(url)) {
    throw new Error('Invalid URL');
  }
  const response = await fetch(url);
  return response.json();
}

function validateUrl(url: string): boolean {
  const parsed = new URL(url);
  return parsed.hostname === 'api.trusted.com';
}
