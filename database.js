const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const path = require('path');

const dbPath = path.resolve(__dirname, 'database.sqlite');
const db = new sqlite3.Database(dbPath, (err) => {
    if (err) {
        console.error('Error connecting to database:', err.message);
    } else {
        console.log('Connected to SQLite database.');
    }
});

db.serialize(() => {
    // 1. Buat tabel users jika belum ada
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT
    )`);

    // 2. Cek apakah kolom 'role' sudah ada (Migrasi manual)
    db.all("PRAGMA table_info(users)", (err, columns) => {
        if (err) {
            console.error("Error checking columns:", err);
            return;
        }
        
        // Migrasi Role
        const hasRoleColumn = columns.some(col => col.name === 'role');
        if (!hasRoleColumn) {
            console.log("Adding 'role' column to users table...");
            db.run("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'member'", (err) => {
                if (err) console.error("Error adding role column:", err);
                else {
                    console.log("Column 'role' added successfully.");
                    db.run("UPDATE users SET role = 'superadmin' WHERE username = 'admin'");
                }
            });
        }

        // Migrasi Balance (Komisi)
        const hasBalanceColumn = columns.some(col => col.name === 'balance');
        if (!hasBalanceColumn) {
            console.log("Adding 'balance' column to users table...");
            db.run("ALTER TABLE users ADD COLUMN balance INTEGER DEFAULT 0", (err) => {
                if (err) console.error("Error adding balance column:", err);
                else console.log("Column 'balance' added successfully.");
            });
        }
    });

    // 3. Buat tabel withdrawals (Penarikan)
    db.run(`CREATE TABLE IF NOT EXISTS withdrawals (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        amount INTEGER,
        account_name TEXT,
        bank_name TEXT,
        account_number TEXT,
        whatsapp TEXT,
        status TEXT DEFAULT 'pending', -- pending, approved, rejected
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )`);

    // 4. Buat tabel blast_logs (Riwayat Blast)
    db.run(`CREATE TABLE IF NOT EXISTS blast_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        admin_id INTEGER,
        sender_mode TEXT,
        total_target INTEGER,
        success_count INTEGER DEFAULT 0,
        failed_count INTEGER DEFAULT 0,
        status TEXT DEFAULT 'running',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // 5. Buat tabel blast_log_details (Detail per nomor)
    db.run(`CREATE TABLE IF NOT EXISTS blast_log_details (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        blast_id INTEGER,
        sender_id INTEGER,
        target_number TEXT,
        status TEXT,
        error_msg TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(blast_id) REFERENCES blast_logs(id)
    )`);

    // 6. Buat default admin jika belum ada
    db.get("SELECT * FROM users WHERE username = ?", ['admin'], (err, row) => {
        if (!row) {
            const salt = bcrypt.genSaltSync(10);
            const hash = bcrypt.hashSync('admin123', salt);
            // Default admin is superadmin
            db.run("INSERT INTO users (username, password, role, balance) VALUES (?, ?, ?, ?)", ['admin', hash, 'superadmin', 0], (err) => {
                if (err) console.error(err.message);
                else console.log('Default admin user created (user: admin, pass: admin123, role: superadmin)');
            });
        } else {
            // Pastikan user 'admin' selalu superadmin
            if (row.role !== 'superadmin') {
                db.run("UPDATE users SET role = 'superadmin' WHERE username = 'admin'");
            }
        }
    });
});

module.exports = db;
