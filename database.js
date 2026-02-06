const sqlite3 = require('sqlite3').verbose();
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');

// --- Configuration ---
// Priority: DATABASE_URL (Railway/Postgres) -> Local SQLite
const isProduction = !!process.env.DATABASE_URL;

let db;
let dbAdapter;

if (isProduction) {
    console.log("Using PostgreSQL Database");
    // Create PG Pool
    const pool = new Pool({
        connectionString: process.env.DATABASE_URL,
        ssl: { rejectUnauthorized: false } // Required for Railway
    });

    // --- PG Adapter to match SQLite API ---
    dbAdapter = {
        pool: pool,
        
        // Helper to convert ? placeholders to $1, $2, etc.
        convertSql: (sql) => {
            let i = 1;
            return sql.replace(/\?/g, () => `$${i++}`);
        },

        run: function(sql, params = [], callback) {
            // Support call without params
            if (typeof params === 'function') {
                callback = params;
                params = [];
            }
            
            const pgSql = this.convertSql(sql);
            pool.query(pgSql, params, (err, res) => {
                if (callback) {
                    // Context for 'this' in callback (sqlite style)
                    const context = {
                        lastID: res?.rows[0]?.id || 0, // PG requires RETURNING id to get lastID
                        changes: res?.rowCount || 0
                    };
                    callback.call(context, err);
                }
            });
        },

        get: function(sql, params = [], callback) {
            if (typeof params === 'function') {
                callback = params;
                params = [];
            }
            const pgSql = this.convertSql(sql);
            pool.query(pgSql, params, (err, res) => {
                if (callback) callback(err, res?.rows[0]);
            });
        },

        all: function(sql, params = [], callback) {
            if (typeof params === 'function') {
                callback = params;
                params = [];
            }
            const pgSql = this.convertSql(sql);
            pool.query(pgSql, params, (err, res) => {
                if (callback) callback(err, res?.rows);
            });
        },
        
        // Explicitly for raw PG access if needed
        query: (text, params) => pool.query(text, params)
    };
    
    // Init PG with Retry Logic
    initPg(pool);

} else {
    console.log("Using SQLite Database (Local)");
    // SQLite connection
    const sqliteDb = new sqlite3.Database('./whatsapp-blast.db', (err) => {
        if (err) console.error('Database opening error: ', err);
        else {
            console.log('Connected to SQLite database.');
            initSqlite(sqliteDb);
        }
    });

    // Pass-through adapter
    dbAdapter = sqliteDb;
}

// --- Initialization Functions ---

const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));

// 1. PostgreSQL Initialization
async function initPg(pool) {
    let retries = 10;
    while (retries > 0) {
        let client;
        try {
            client = await pool.connect();
            console.log("Initializing PG Tables...");
            
            await client.query(`
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    username TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL,
                    role TEXT DEFAULT 'member',
                    phone TEXT,
                    balance INTEGER DEFAULT 0,
                    inactive_notified BOOLEAN DEFAULT FALSE,
                    referral_code TEXT UNIQUE,
                    referred_by INTEGER
                );
            `);

            await client.query(`
                CREATE TABLE IF NOT EXISTS withdrawals (
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER REFERENCES users(id),
                    amount INTEGER,
                    account_name TEXT,
                    bank_name TEXT,
                    account_number TEXT,
                    whatsapp TEXT,
                    status TEXT DEFAULT 'pending',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            `);

            await client.query(`
                CREATE TABLE IF NOT EXISTS topups (
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER REFERENCES users(id),
                    amount INTEGER,
                    payment_method TEXT,
                    status TEXT DEFAULT 'pending',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            `);

            await client.query(`
                CREATE TABLE IF NOT EXISTS admin_banks (
                    id SERIAL PRIMARY KEY,
                    bank_name TEXT,
                    account_number TEXT,
                    account_name TEXT,
                    is_active BOOLEAN DEFAULT TRUE
                );
            `);

            await client.query(`
                CREATE TABLE IF NOT EXISTS whatsapp_sessions (
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER REFERENCES users(id),
                    session_name TEXT,
                    session_id TEXT UNIQUE,
                    status TEXT DEFAULT 'disconnected',
                    device_info TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            `);

            await client.query(`
                CREATE TABLE IF NOT EXISTS referral_commissions (
                    id SERIAL PRIMARY KEY,
                    referrer_id INTEGER REFERENCES users(id),
                    referred_user_id INTEGER REFERENCES users(id),
                    amount INTEGER,
                    description TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            `);

            await client.query(`
                CREATE TABLE IF NOT EXISTS blast_logs (
                    id SERIAL PRIMARY KEY,
                    admin_id INTEGER,
                    sender_mode TEXT,
                    total_target INTEGER,
                    success_count INTEGER DEFAULT 0,
                    failed_count INTEGER DEFAULT 0,
                    status TEXT DEFAULT 'running',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            `);

            await client.query(`
                CREATE TABLE IF NOT EXISTS blast_log_details (
                    id SERIAL PRIMARY KEY,
                    blast_id INTEGER REFERENCES blast_logs(id),
                    sender_id INTEGER,
                    target_number TEXT,
                    status TEXT,
                    error_msg TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            `);

            // --- Auto Migration for missing columns ---
            try {
                console.log("Checking for schema migrations...");
                await client.query("ALTER TABLE users ADD COLUMN IF NOT EXISTS phone TEXT");
                await client.query("ALTER TABLE users ADD COLUMN IF NOT EXISTS inactive_notified BOOLEAN DEFAULT FALSE");
                await client.query("ALTER TABLE users ADD COLUMN IF NOT EXISTS referral_code TEXT UNIQUE");
                await client.query("ALTER TABLE users ADD COLUMN IF NOT EXISTS referred_by INTEGER");
                await client.query("ALTER TABLE users ADD COLUMN IF NOT EXISTS bank_name TEXT");
                await client.query("ALTER TABLE users ADD COLUMN IF NOT EXISTS account_number TEXT");
                await client.query("ALTER TABLE users ADD COLUMN IF NOT EXISTS account_name TEXT");
                console.log("Schema migration completed.");
            } catch (err) {
                console.error("Migration Warning (Non-fatal):", err.message);
            }

            // Create Default Admin
            const res = await client.query("SELECT * FROM users WHERE username = $1", ['admin']);
            if (res.rows.length === 0) {
                const salt = bcrypt.genSaltSync(10);
                const hash = bcrypt.hashSync('admin123', salt);
                await client.query("INSERT INTO users (username, password, role, balance) VALUES ($1, $2, 'superadmin', 0)", ['admin', hash]);
                console.log("Default admin created (PG).");
            }

            console.log("PG Tables Initialized Successfully.");
            break; // Success
        } catch (err) {
            console.error(`PG Init Attempt Failed (Retries left: ${retries}):`, err.message);
            retries--;
            if (retries === 0) console.error("PG Init Failed after multiple attempts.");
            else await sleep(5000);
        } finally {
            if (client) client.release();
        }
    }
}

// 2. SQLite Initialization
function initSqlite(db) {
    db.serialize(() => {
        db.run(`CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'member',
            phone TEXT,
            balance INTEGER DEFAULT 0,
            inactive_notified BOOLEAN DEFAULT FALSE,
            referral_code TEXT UNIQUE,
            referred_by INTEGER,
            bank_name TEXT,
            account_number TEXT,
            account_name TEXT
        )`);

        db.run(`CREATE TABLE IF NOT EXISTS withdrawals (
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

        db.run(`CREATE TABLE IF NOT EXISTS topups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            amount INTEGER,
            payment_method TEXT,
            status TEXT DEFAULT 'pending',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )`);

        db.run(`CREATE TABLE IF NOT EXISTS admin_banks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            bank_name TEXT,
            account_number TEXT,
            account_name TEXT,
            is_active BOOLEAN DEFAULT 1
        )`);

        db.run(`CREATE TABLE IF NOT EXISTS whatsapp_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            session_name TEXT,
            session_id TEXT UNIQUE,
            status TEXT DEFAULT 'disconnected',
            device_info TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )`);

        db.run(`CREATE TABLE IF NOT EXISTS referral_commissions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            referrer_id INTEGER,
            referred_user_id INTEGER,
            amount INTEGER,
            description TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(referrer_id) REFERENCES users(id)
        )`);

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

        // --- SQLite Auto Migration ---
        const migrations = [
            "ALTER TABLE users ADD COLUMN bank_name TEXT",
            "ALTER TABLE users ADD COLUMN account_number TEXT",
            "ALTER TABLE users ADD COLUMN account_name TEXT"
        ];

        migrations.forEach(sql => {
            db.run(sql, (err) => {
                // Ignore error if column exists
            });
        });

        db.get("SELECT * FROM users WHERE username = 'admin'", (err, row) => {
            if (!row) {
                const salt = bcrypt.genSaltSync(10);
                const hash = bcrypt.hashSync('admin123', salt);
                db.run("INSERT INTO users (username, password, role, balance) VALUES (?, ?, ?, ?)", 
                    ['admin', hash, 'superadmin', 0]);
                console.log("Default admin created (SQLite).");
            }
        });
    });
}

module.exports = dbAdapter;