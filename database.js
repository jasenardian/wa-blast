const { Pool } = require('pg');
const bcrypt = require('bcryptjs');

// Determine database configuration
// Priority: DATABASE_URL (Railway/Cloud) -> Local SQLite (Deprecated/Fallback if needed, but we are switching to PG)
const isProduction = process.env.NODE_ENV === 'production' || process.env.DATABASE_URL;

let db;

if (isProduction) {
    console.log("Using PostgreSQL Database");
    db = new Pool({
        connectionString: process.env.DATABASE_URL,
        ssl: { rejectUnauthorized: false } // Required for Railway/Heroku
    });
} else {
    // Local Development Fallback to SQLite (Optional: Better to use local PG if possible)
    // For now, let's stick to PG logic to ensure consistency.
    // If you run locally, provide DATABASE_URL in .env
    console.log("Using PostgreSQL Database (Local Dev)");
    db = new Pool({
        // Use connection string if available, otherwise default to local pg
        connectionString: process.env.DATABASE_URL,
    });
}

// Wrapper for Query to match SQLite style callback if needed, or better: use Async/Await everywhere in app.js
// Since app.js uses db.run, db.get, db.all (SQLite API), we need a compatibility layer or refactor app.js.
// REFACTORING app.js IS SAFER. But for quick migration, let's create a compatibility layer.

const dbAdapter = {
    // Execute a query that returns no rows (INSERT, UPDATE, DELETE)
    run: (sql, params = [], callback) => {
        // Convert SQLite ? placeholders to PG $1, $2...
        let paramIndex = 1;
        const pgSql = sql.replace(/\?/g, () => `$${paramIndex++}`);
        
        db.query(pgSql, params, (err, res) => {
            if (callback) {
                // SQLite callback: function(err) { this.lastID, this.changes }
                const context = { 
                    lastID: res?.rows[0]?.id || 0, // PG requires RETURNING id for lastID
                    changes: res?.rowCount || 0
                };
                callback.call(context, err);
            }
        });
    },

    // Execute a query that returns a single row
    get: (sql, params = [], callback) => {
        let paramIndex = 1;
        const pgSql = sql.replace(/\?/g, () => `$${paramIndex++}`);

        db.query(pgSql, params, (err, res) => {
            if (callback) callback(err, res?.rows[0]);
        });
    },

    // Execute a query that returns multiple rows
    all: (sql, params = [], callback) => {
        let paramIndex = 1;
        const pgSql = sql.replace(/\?/g, () => `$${paramIndex++}`);

        db.query(pgSql, params, (err, res) => {
            if (callback) callback(err, res?.rows);
        });
    }
};

// --- MIGRATION SCRIPT FOR POSTGRES ---
const initDb = async () => {
    // Only attempt connection if DB is configured (avoids crash on local if no PG running)
    if (!process.env.DATABASE_URL && !isProduction) {
         console.warn("WARNING: No DATABASE_URL provided. PostgreSQL init skipped. Application may crash if DB is accessed.");
         return;
    }

    try {
        const client = await db.connect();
        try {
            console.log("Initializing PostgreSQL Tables...");

            // Users
            await client.query(`
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    username TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL,
                    role TEXT DEFAULT 'member',
                    balance INTEGER DEFAULT 0,
                    referral_code TEXT UNIQUE,
                    referred_by INTEGER
                );
            `);

            // Withdrawals
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

            // Sessions
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

            // Referral Commissions
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

            // Blast Logs
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

            // Blast Details
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

            // Default Admin
            const adminCheck = await client.query("SELECT * FROM users WHERE username = $1", ['admin']);
            if (adminCheck.rows.length === 0) {
                const salt = bcrypt.genSaltSync(10);
                const hash = bcrypt.hashSync('admin123', salt);
                await client.query(
                    "INSERT INTO users (username, password, role, balance) VALUES ($1, $2, $3, $4)",
                    ['admin', hash, 'superadmin', 0]
                );
                console.log("Default admin created (PG).");
            }

            console.log("PostgreSQL Initialization Complete.");
        } finally {
            client.release();
        }
    } catch (err) {
        console.error("PostgreSQL Init Error:", err);
    }
};

initDb();

module.exports = dbAdapter;
