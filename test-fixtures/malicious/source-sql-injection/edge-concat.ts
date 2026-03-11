// Edge case: string concatenation in query — should trigger HIGH
export async function searchUsers(name: string, db: any) {
  const result = await db.query('SELECT * FROM users WHERE name = ' + name);
  return result.rows;
}
