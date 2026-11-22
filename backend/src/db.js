import pg from 'pg';
import dotenv from 'dotenv';

dotenv.config();

const { Pool } = pg;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

pool.on('error', (err) => {
  console.error('[db] unexpected pool error', err.message);
});

// Converts SQLite ? placeholders to PostgreSQL $1, $2, ...
function toPg(sql) {
  let i = 0;
  return sql.replace(/\?/g, () => `$${++i}`);
}

export async function dbGet(sql, params = []) {
  const { rows } = await pool.query(toPg(sql), params);
  return rows[0] ?? null;
}

export async function dbAll(sql, params = []) {
  const { rows } = await pool.query(toPg(sql), params);
  return rows;
}

export async function dbRun(sql, params = []) {
  return pool.query(toPg(sql), params);
}

export default pool;
