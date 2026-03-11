// Safe: parameterized query with placeholder
async function findUser(id: string, db: any) {
  const result = await db.query('SELECT * FROM users WHERE id = $1', [id]);
  return result.rows;
}

// Safe: static query
async function listUsers(db: any) {
  const result = await db.query('SELECT * FROM users');
  return result.rows;
}
