export const EXEC_SINKS = [
  'child_process.exec',
  'child_process.execSync',
  'execSync',
  'exec',
  'eval',
];

export const EXEC_SINKS_WITH_SHELL = [
  'child_process.spawn',
  'spawn',
];

export const FETCH_SINKS = [
  'fetch',
  'axios.get',
  'axios.post',
  'axios.put',
  'axios.delete',
  'axios.request',
  'axios',
  'http.request',
  'https.request',
  'got',
  'got.get',
  'got.post',
];

export const FILE_SINKS = [
  'fs.readFile',
  'fs.readFileSync',
  'fs.writeFile',
  'fs.writeFileSync',
  'fs.unlink',
  'fs.unlinkSync',
  'fs.access',
  'fs.accessSync',
  'readFile',
  'readFileSync',
  'writeFile',
  'writeFileSync',
];

// Directory listing sinks — not SC-003 (no file content exposure)
export const DIRECTORY_SINKS = [
  'fs.readdir',
  'fs.readdirSync',
  'readdirSync',
  'readdir',
];

export const QUERY_SINKS = [
  '.query',
  '.execute',
  'db.run',
  'db.all',
  'db.get',
  'pool.query',
  'client.query',
  'connection.query',
  'knex.raw',
];

// Python sinks
export const PY_EXEC_SINKS = [
  'os.system',
  'os.popen',
  'subprocess.call',
  'subprocess.run',
  'subprocess.Popen',
  'subprocess.check_output',
  'subprocess.check_call',
  'eval',
  'exec',
];

export const PY_FETCH_SINKS = [
  'requests.get',
  'requests.post',
  'requests.put',
  'requests.delete',
  'urllib.request.urlopen',
  'httpx.get',
  'httpx.post',
];

export const PY_FILE_SINKS = ['open'];

export const PY_QUERY_SINKS = ['cursor.execute', 'cursor.executemany'];
