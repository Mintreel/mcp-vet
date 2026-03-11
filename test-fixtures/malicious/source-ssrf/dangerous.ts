// Dangerous: unvalidated URL from parameter
async function fetchUrl(url: string) {
  const response = await fetch(url);
  return response.json();
}

// Dangerous: URL from request body
async function proxyRequest(req: { body: { url: string } }) {
  const data = await fetch(req.body.url);
  return data.text();
}
