// Edge case: allowlist check before fetch — should NOT trigger
const ALLOWED_HOSTS = ['api.example.com', 'cdn.example.com'];

export async function fetchWithAllowlist(url: string) {
  const parsed = new URL(url);
  if (!allowlist(parsed.hostname)) {
    throw new Error('Host not in allowlist');
  }
  const response = await fetch(url);
  return response.json();
}

function allowlist(host: string): boolean {
  return ALLOWED_HOSTS.includes(host);
}
