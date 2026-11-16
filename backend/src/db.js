import pg from 'pg';
const { Pool } = pg;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// Auto-convert SQLite ? placeholders to PostgreSQL $1 $2 $3...
function toPostgres(sql) {
  let i = 0;
  return sql.replace(/\?/g, () => `$${++i}`);
}

function prepare(sql) {
  const pgSql = toPostgres(sql);
  return {
    async get(...args) {
      const params = args.flat();
      const { rows } = await pool.query(pgSql, params);
      return rows[0] ?? null;
    },
    async all(...args) {
      const params = args.flat();
      const { rows } = await pool.query(pgSql, params);
      return rows;
    },
    async run(...args) {
      const params = args.flat();
      await pool.query(pgSql, params);
    }
  };
}

const db = { prepare, pool };
export default db;
