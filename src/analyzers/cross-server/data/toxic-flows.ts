export interface ToxicFlow {
  path: [string, string];
  risk: string;
}

export const TOXIC_FLOWS: ToxicFlow[] = [
  { path: ['READ_SECRETS', 'HTTP_OUT'], risk: 'Credential exfiltration' },
  { path: ['READ_FILES', 'HTTP_OUT'], risk: 'File exfiltration' },
  { path: ['READ_FILES', 'SEND_EMAIL'], risk: 'Data leak via email' },
  { path: ['DB_ACCESS', 'HTTP_OUT'], risk: 'Database exfiltration' },
  { path: ['READ_FILES', 'EXEC_CODE'], risk: 'Read + execute chain' },
  { path: ['WRITE_FILES', 'EXEC_CODE'], risk: 'Write + execute = RCE' },
  { path: ['DB_ACCESS', 'SEND_EMAIL'], risk: 'Database leak via email' },
  { path: ['READ_SECRETS', 'SEND_EMAIL'], risk: 'Credential leak via email' },
];
