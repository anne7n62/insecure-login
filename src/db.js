import { DatabaseSync } from "node:sqlite";

const db = new DatabaseSync("./app.db");

export const run = (sql) =>
  new Promise((resolve, reject) => {
    try {
      const result = db.prepare(sql).run();
      resolve(result);
    } catch (err) {
      reject(err);
    }
  });

export const get = (sql) =>
  new Promise((resolve, reject) => {
    try {
      const row = db.prepare(sql).get();
      resolve(row);
    } catch (err) {
      reject(err);
    }
  });

export const all = (sql) =>
  new Promise((resolve, reject) => {
    try {
      const rows = db.prepare(sql).all();
      resolve(rows);
    } catch (err) {
      reject(err);
    }
  });

export const init = async () => {
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'user'
    );
  `);

  const existing = await get(`SELECT id FROM users WHERE email='test@test.dev'`);
  if (!existing) {
    await run(`
      INSERT INTO users (email, password, role)
      VALUES ('test@test.dev', 'test1234', 'admin');
    `);
  }
};
