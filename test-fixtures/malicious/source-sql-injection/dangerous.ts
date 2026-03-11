// Dangerous: template literal without tag
async function findUser(id: string, db: any) {
  const result = await db.query(`SELECT * FROM users WHERE id = ${id}`);
  return result.rows;
}

// Dangerous: string concatenation
async function searchUsers(name: string, db: any) {
  const result = await db.query('SELECT * FROM users WHERE name = ' + name);
  return result.rows;
}
