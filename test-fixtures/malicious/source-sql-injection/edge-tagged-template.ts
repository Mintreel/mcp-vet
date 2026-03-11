// Edge case: tagged template literal — should NOT trigger
// Tagged templates are parameterized by the tag function (e.g., sql from a query builder)
declare function sql(strings: TemplateStringsArray, ...values: any[]): string;

export async function findUser(id: string, db: any) {
  const result = await db.query(sql`SELECT * FROM users WHERE id = ${id}`);
  return result.rows;
}
