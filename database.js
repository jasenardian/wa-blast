const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const bcrypt = require('bcryptjs');

const dbPath = path.resolve(__dirname, 'database.sqlite');
const db = new sqlite3.Database(dbPath, (err) => {
    if (err) console.error('Error connecting to database:', err.message);
    else console.log('Connected to SQLite database.');
});

// Helper untuk menjalankan query migrasi secara berurutan (Promise-based)
function runMigration(query, params = []) {
    return new Promise((resolve, reject) => {
        db.run(query, params, function(err) {
            if (err) {
                // Ignore "duplicate column name" error (SQLITE_ERROR) if we use simple ADD COLUMN
                if (err.message.includes('duplicate column name')) {
                    resolve();
                } else {
                    reject(err);
                }
            } else {
                resolve(this);
            }
        });
    });
}

function getTableInfo(tableName) {
    return new Promise((resolve, reject) => {
        db.all(`PRAGMA table_info(${tableName})`, (err, rows) => {
            if (err) reject(err);
            else resolve(rows);
        });
    });
}

db.serialize(async () => {
    try {
        // 1. Base Tables
        await runMigration(`CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT
        )`);

        await runMigration(`CREATE TABLE IF NOT EXISTS withdrawals (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            amount INTEGER,
            account_name TEXT,
            bank_name TEXT,
            account_number TEXT,
            whatsapp TEXT,
            status TEXT DEFAULT 'pending',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )`);

        await runMigration(`CREATE TABLE IF NOT EXISTS whatsapp_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            session_name TEXT,
            session_id TEXT UNIQUE,
            status TEXT DEFAULT 'disconnected',
            device_info TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )`);

        await runMigration(`CREATE TABLE IF NOT EXISTS referral_commissions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            referrer_id INTEGER,
            referred_user_id INTEGER,
            amount INTEGER,
            description TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(referrer_id) REFERENCES users(id),
            FOREIGN KEY(referred_user_id) REFERENCES users(id)
        )`);

        await runMigration(`CREATE TABLE IF NOT EXISTS blast_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            admin_id INTEGER,
            sender_mode TEXT,
            total_target INTEGER,
            success_count INTEGER DEFAULT 0,
            failed_count INTEGER DEFAULT 0,
            status TEXT DEFAULT 'running',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )`);

        await runMigration(`CREATE TABLE IF NOT EXISTS blast_log_details (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            blast_id INTEGER,
            sender_id INTEGER,
            target_number TEXT,
            status TEXT,
            error_msg TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(blast_id) REFERENCES blast_logs(id)
        )`);

        // 2. Check and Add Columns for 'users'
        const columns = await getTableInfo('users');
        const colNames = columns.map(c => c.name);

        if (!colNames.includes('role')) {
            console.log("Migrating: Adding 'role' to users...");
            await runMigration("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'member'");
            await runMigration("UPDATE users SET role = 'superadmin' WHERE username = 'admin'");
        }

        if (!colNames.includes('balance')) {
            console.log("Migrating: Adding 'balance' to users...");
            await runMigration("ALTER TABLE users ADD COLUMN balance INTEGER DEFAULT 0");
        }

        if (!colNames.includes('referral_code')) {
            console.log("Migrating: Adding 'referral_code' to users...");
            // SQLite does not support adding UNIQUE constraints via ALTER TABLE ADD COLUMN
            // We must add the column first without UNIQUE, then handle uniqueness via application logic or recreate table (complex)
            // For simplicity in this existing production DB, we add it as standard TEXT, then we can add a unique index.
            
            await runMigration("ALTER TABLE users ADD COLUMN referral_code TEXT");
            await runMigration("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_referral_code ON users(referral_code)");
            
            // Generate codes for existing
            db.all("SELECT id, username FROM users", (err, rows) => {
                if(rows) {
                    rows.forEach(user => {
                        const code = (user.username.substring(0, 3) + Math.random().toString(36).substring(2, 5)).toUpperCase();
                        db.run("UPDATE users SET referral_code = ? WHERE id = ? AND referral_code IS NULL", [code, user.id]);
                    });
                }
            });
        }

        if (!colNames.includes('referred_by')) {
            console.log("Migrating: Adding 'referred_by' to users...");
            await runMigration("ALTER TABLE users ADD COLUMN referred_by INTEGER");
        }

        // 3. Ensure Admin Exists
        db.get("SELECT * FROM users WHERE username = ?", ['admin'], (err, row) => {
            if (!row) {
                const salt = bcrypt.genSaltSync(10);
                const hash = bcrypt.hashSync('admin123', salt);
                db.run("INSERT INTO users (username, password, role, balance) VALUES (?, ?, ?, ?)", ['admin', hash, 'superadmin', 0], (err) => {
                    if (!err) console.log('Default admin created.');
                });
            } else {
                if (row.role !== 'superadmin') {
                    db.run("UPDATE users SET role = 'superadmin' WHERE username = 'admin'");
                }
            }
        });

        console.log("Database verification/migration complete.");

    } catch (error) {
        console.error("Migration Error:", error);
    }
});

module.exports = db;
