// Safe: static URL
async function fetchGitHub() {
  const response = await fetch('https://api.github.com/repos');
  return response.json();
}

// Safe: URL validation before fetch
async function fetchValidated(url: string) {
  if (!validateUrl(url)) throw new Error('Invalid URL');
  const response = await fetch(url);
  return response.json();
}

function validateUrl(url: string): boolean {
  const parsed = new URL(url);
  return parsed.hostname === 'api.example.com';
}
