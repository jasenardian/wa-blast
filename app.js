const { Client, LocalAuth } = require('whatsapp-web.js');
const express = require('express');
const socketIO = require('socket.io');
const qrcode = require('qrcode');
const http = require('http');
const fs = require('fs');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const db = require('./database');
const TelegramBot = require('node-telegram-bot-api');
const cors = require('cors');

const app = express();
app.set('trust proxy', 1); // Trust first proxy (Required for Railway/Heroku/Render)
const server = http.createServer(app);
const io = socketIO(server, {
    cors: {
        origin: "*", // Izinkan semua origin (untuk frontend di hosting lain)
        methods: ["GET", "POST"]
    }
});

// --- Konfigurasi Telegram Bot ---
const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN || '7241784386:AAGFfDY6AM4Oz7z1rap30uFiOuewkg04d4A';
const TELEGRAM_CHAT_ID = process.env.TELEGRAM_CHAT_ID || '6076369736'; 

let bot = null;
if (TELEGRAM_BOT_TOKEN && TELEGRAM_BOT_TOKEN !== 'YOUR_TOKEN_HERE') {
    try {
        bot = new TelegramBot(TELEGRAM_BOT_TOKEN, { polling: false }); 
        console.log('Telegram Bot Initialized');
    } catch (error) {
        console.error('Telegram Bot Error:', error.message);
    }
}

// Map untuk menyimpan sesi client WhatsApp
// Key: dbSessionId (Integer) -> Value: Client Instance
const sessions = new Map(); 

// --- Konfigurasi Middleware ---
app.use(cors({
    origin: true, 
    credentials: true 
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Setup Session
const sessionMiddleware = session({
    secret: 'secret-key-wajib-ganti-nanti',
    resave: false,
    saveUninitialized: false,
    cookie: { 
        maxAge: 24 * 60 * 60 * 1000, // 1 hari
        secure: process.env.NODE_ENV === 'production', 
        sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax'
    }
});
app.use(sessionMiddleware);

// --- Helper Functions ---
function isAuthenticated(req, res, next) {
    if (req.session.userId) {
        return next();
    }
    res.redirect('/login');
}

function isSuperAdmin(req, res, next) {
    if (req.session.role === 'superadmin') {
        return next();
    }
    res.status(403).json({ status: 'error', message: 'Access Denied: Superadmin only' });
}

function spintax(text) {
    const pattern = /\{([^{}]+)\}/g;
    while (pattern.test(text)) {
        text = text.replace(pattern, function (match, p1) {
            const options = p1.split('|');
            return options[Math.floor(Math.random() * options.length)];
        });
    }
    return text;
}

const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));

function updateBalance(userId, amount) {
    db.run("UPDATE users SET balance = COALESCE(balance, 0) + ? WHERE id = ?", [amount, userId], (err) => {
        if (err) console.error("Error updating balance:", err.message);
        else console.log(`Added Rp ${amount} to User ${userId}`);
    });
}

function sendTelegramNotification(message) {
    return new Promise((resolve) => {
        if (bot && TELEGRAM_CHAT_ID) {
            bot.sendMessage(TELEGRAM_CHAT_ID, message)
                .then(() => resolve())
                .catch(err => {
                    console.error('Failed to send Telegram message:', err.message);
                    resolve(); 
                });
        } else {
            console.log('Telegram Bot not configured. Message skipped:', message);
            resolve();
        }
    });
}

// Fungsi Init Client
// dbSessionId: ID from whatsapp_sessions table
// userId: Owner ID
// customSessionId: Optional, used for migration of old sessions (e.g. 'user-1')
function initializeClient(dbSessionId, userId, customSessionId = null) {
    if (sessions.has(dbSessionId)) {
        return sessions.get(dbSessionId);
    }

    const clientId = customSessionId || `session-${dbSessionId}`;
    console.log(`Initializing client for Session ID: ${dbSessionId} (Client ID: ${clientId})`);

    const client = new Client({
        restartOnAuthFail: true,
        puppeteer: {
            headless: true,
            executablePath: process.env.PUPPETEER_EXECUTABLE_PATH || undefined, // Use installed Chromium on Railway
            args: [
                '--no-sandbox',
                '--disable-setuid-sandbox',
                '--disable-dev-shm-usage',
                '--disable-accelerated-2d-canvas',
                '--no-first-run',
                '--no-zygote',
                '--single-process',
                '--disable-gpu'
            ],
        },
        authStrategy: new LocalAuth({ clientId: clientId })
    });

    // Update status to scanning/init
    db.run("UPDATE whatsapp_sessions SET status = 'scanning' WHERE id = ?", [dbSessionId]);

    client.on('qr', (qr) => {
        console.log(`QR RECEIVED for Session ${dbSessionId}`);
        qrcode.toDataURL(qr, (err, url) => {
            // Emit to specific user room, but with session info
            io.to(userId.toString()).emit('qr', { sessionId: dbSessionId, url: url });
            io.to(userId.toString()).emit('message', `QR Code untuk sesi #${dbSessionId} diterima, silakan scan!`);
        });
    });

    client.on('ready', () => {
        const info = client.info;
        const device_info = JSON.stringify({
            pushname: info.pushname,
            wid: info.wid,
            platform: info.platform
        });
        
        db.run("UPDATE whatsapp_sessions SET status = 'connected', device_info = ? WHERE id = ?", [device_info, dbSessionId]);
        
        io.to(userId.toString()).emit('ready', { sessionId: dbSessionId });
        io.to(userId.toString()).emit('message', `Whatsapp Sesi #${dbSessionId} is ready!`);
        console.log(`Session ${dbSessionId} is ready!`);
    });

    client.on('authenticated', () => {
        io.to(userId.toString()).emit('authenticated', { sessionId: dbSessionId });
        io.to(userId.toString()).emit('message', `Whatsapp Sesi #${dbSessionId} is authenticated!`);
        console.log(`Session ${dbSessionId} AUTHENTICATED`);
    });

    client.on('auth_failure', function(session) {
        io.to(userId.toString()).emit('message', `Auth failure on Session #${dbSessionId}, restarting...`);
        db.run("UPDATE whatsapp_sessions SET status = 'disconnected' WHERE id = ?", [dbSessionId]);
    });

    client.on('disconnected', (reason) => {
        io.to(userId.toString()).emit('disconnected', { sessionId: dbSessionId });
        io.to(userId.toString()).emit('message', `Whatsapp Sesi #${dbSessionId} is disconnected!`);
        db.run("UPDATE whatsapp_sessions SET status = 'disconnected' WHERE id = ?", [dbSessionId]);
        
        client.destroy().catch(e => console.error('Error destroying client:', e.message));
        sessions.delete(dbSessionId);
    });

    client.initialize().catch(err => {
        console.error(`Failed to initialize client for Session ${dbSessionId}:`, err.message);
        io.to(userId.toString()).emit('message', `Gagal inisialisasi sesi #${dbSessionId}: ${err.message}`);
    });

    sessions.set(dbSessionId, client);
    return client;
}

// --- Global Error Handlers ---
process.on('unhandledRejection', (reason, promise) => {
    console.error('⚠️ Unhandled Rejection:', reason.message || reason);
});

process.on('uncaughtException', (err) => {
    console.error('⚠️ Uncaught Exception:', err.message || err);
});

process.on('SIGINT', () => {
    console.log('Server stopping...');
    process.exit(0);
});

process.on('SIGTERM', () => {
    console.log('Server stopping...');
    process.exit(0);
});

// --- Routes ---

app.get('/login', (req, res) => {
    if (req.session.userId) return res.redirect('/');
    res.sendFile('login.html', { root: __dirname });
});

app.get('/register', (req, res) => {
    if (req.session.userId) return res.redirect('/');
    res.sendFile('register.html', { root: __dirname });
});

app.get('/riwayat_blast.html', isAuthenticated, isSuperAdmin, (req, res) => {
    res.sendFile('riwayat_blast.html', { root: __dirname });
});

// Register with Referral
app.post('/register', (req, res) => {
    const { username, password, referralCode } = req.body;
    
    if (!username || !password) {
        return res.json({ status: 'error', message: 'Username dan password harus diisi!' });
    }

    db.get("SELECT * FROM users WHERE username = ?", [username], (err, user) => {
        if (user) {
            return res.json({ status: 'error', message: 'Username sudah digunakan!' });
        }

        let referredBy = null;
        const checkReferral = new Promise((resolve, reject) => {
            if (referralCode) {
                db.get("SELECT id FROM users WHERE referral_code = ?", [referralCode], (err, refUser) => {
                    if (refUser) referredBy = refUser.id;
                    resolve();
                });
            } else {
                resolve();
            }
        });

        checkReferral.then(() => {
            const salt = bcrypt.genSaltSync(10);
            const hash = bcrypt.hashSync(password, salt);
            // Generate own referral code
            const ownRefCode = (username.substring(0, 3) + Math.random().toString(36).substring(2, 5)).toUpperCase();

            db.run("INSERT INTO users (username, password, role, balance, referral_code, referred_by) VALUES (?, ?, ?, ?, ?, ?)", 
                [username, hash, 'member', 0, ownRefCode, referredBy], function(err) {
                if (err) {
                    return res.status(500).json({ status: 'error', message: "Database error: " + err.message });
                }
                res.json({ status: 'success', message: 'Pendaftaran berhasil! Silakan login.' });
            });
        });
    });
});

app.post('/login', (req, res) => {
    const { username, password } = req.body;
    
    db.get("SELECT * FROM users WHERE username = ?", [username], (err, user) => {
        if (err) return res.status(500).json({ status: 'error', message: 'Database error' });
        if (!user) return res.json({ status: 'error', message: 'User tidak ditemukan!' });

        const isMatch = bcrypt.compareSync(password, user.password);
        if (isMatch) {
            req.session.userId = user.id;
            req.session.username = user.username;
            req.session.role = user.role;
            
            // Auto-init all sessions
            db.all("SELECT id, session_id FROM whatsapp_sessions WHERE user_id = ?", [user.id], (err, rows) => {
                if (rows) {
                    rows.forEach(row => initializeClient(row.id, user.id, row.session_id));
                }
            });

            res.json({ status: 'success', message: 'Login berhasil!', redirect: '/' });
        } else {
            res.json({ status: 'error', message: 'Password salah!' });
        }
    });
});

app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/login');
});

app.get('/api/me', isAuthenticated, (req, res) => {
    db.get("SELECT balance, referral_code FROM users WHERE id = ?", [req.session.userId], (err, row) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        
        res.json({
            id: req.session.userId,
            username: req.session.username,
            role: req.session.role,
            balance: row ? row.balance : 0,
            referral_code: row ? row.referral_code : '-'
        });
    });
});

app.get('/api/me/stats', isAuthenticated, (req, res) => {
    const userId = req.session.userId;
    
    // Using Promise.all to run queries in parallel
    const p1 = new Promise(resolve => {
        db.get("SELECT COUNT(*) as total, SUM(CASE WHEN status='connected' THEN 1 ELSE 0 END) as online FROM whatsapp_sessions WHERE user_id = ?", [userId], (err, row) => {
            resolve(row || { total: 0, online: 0 });
        });
    });

    const p2 = new Promise(resolve => {
        db.get("SELECT SUM(success_count) as total_sent FROM blast_logs WHERE admin_id = ?", [userId], (err, row) => {
            resolve(row ? row.total_sent : 0);
        });
    });

    const p3 = new Promise(resolve => {
        // Count Active Referral (Has at least 1 connected device)
        db.get(`
            SELECT COUNT(DISTINCT u.id) as active_refs 
            FROM users u
            JOIN whatsapp_sessions ws ON u.id = ws.user_id 
            WHERE u.referred_by = ? AND ws.status = 'connected'
        `, [userId], (err, row) => {
            resolve(row ? row.active_refs : 0);
        });
    });

    const p4 = new Promise(resolve => {
        // Count Total Referrals
        db.get("SELECT COUNT(*) as total_refs FROM users WHERE referred_by = ?", [userId], (err, row) => {
            resolve(row ? row.total_refs : 0);
        });
    });

    Promise.all([p1, p2, p3, p4]).then(([deviceStats, messageStats, activeRef, totalRef]) => {
        res.json({
            devices_total: deviceStats.total || 0,
            devices_online: deviceStats.online || 0,
            devices_offline: (deviceStats.total - deviceStats.online) || 0,
            messages_sent: messageStats || 0,
            referral_active: activeRef,
            referral_passive: totalRef - activeRef,
            referral_total: totalRef
        });
    }).catch(err => {
        res.status(500).json({ error: err.message });
    });
});

// --- NEW: Device Management APIs ---

// List Devices
app.get('/api/devices', isAuthenticated, (req, res) => {
    db.all("SELECT id, session_name, status, device_info FROM whatsapp_sessions WHERE user_id = ?", [req.session.userId], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        const result = rows.map(row => {
            // Check real-time connection status if possible
            const client = sessions.get(row.id);
            let realStatus = row.status;
            if (client && client.info && client.info.wid) {
                realStatus = 'connected';
            } else if (client) {
                // Client exists but not connected (maybe scanning)
            } else {
                realStatus = 'disconnected';
            }
            return {
                ...row,
                status: realStatus,
                device_info: row.device_info ? JSON.parse(row.device_info) : null
            };
        });
        res.json(result);
    });
});

// Add Device
app.post('/api/devices', isAuthenticated, (req, res) => {
    const { session_name } = req.body;
    const userId = req.session.userId;
    const sessionName = session_name || `Device ${Date.now()}`;
    const uniqueSessionId = `session-${userId}-${Date.now()}`; // Unique for LocalAuth

    db.run("INSERT INTO whatsapp_sessions (user_id, session_name, session_id, status) VALUES (?, ?, ?, ?) RETURNING id", 
        [userId, sessionName, uniqueSessionId, 'disconnected'], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        
        const newDbId = this.lastID;
        initializeClient(newDbId, userId, uniqueSessionId);
        res.json({ status: 'success', message: 'Device added', data: { id: newDbId } });
    });
});

// Delete Device
app.delete('/api/devices/:id', isAuthenticated, (req, res) => {
    const sessionId = parseInt(req.params.id);
    const userId = req.session.userId;

    db.get("SELECT * FROM whatsapp_sessions WHERE id = ? AND user_id = ?", [sessionId, userId], async (err, row) => {
        if (!row) return res.status(404).json({ error: 'Device not found' });

        const client = sessions.get(sessionId);
        if (client) {
            try {
                await client.destroy();
            } catch (e) { console.error(e); }
            sessions.delete(sessionId);
        }

        // Cleanup files
        const sessionPath = `./.wwebjs_auth/session-${row.session_id}`; // Note: initializeClient uses clientId as `session-${dbId}` OR custom
        // Wait, initializeClient logic: `clientId = customSessionId || 'session-' + dbSessionId`
        // In Add Device: we set `session_id` column to `session-{userId}-{timestamp}`.
        // So we should clean up based on that.
        
        try {
            if (fs.existsSync(sessionPath)) {
                fs.rmSync(sessionPath, { recursive: true, force: true });
            }
        } catch (e) {}

        db.run("DELETE FROM whatsapp_sessions WHERE id = ?", [sessionId], (err) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ status: 'success', message: 'Device deleted' });
        });
    });
});

// --- Admin APIs ---

app.get('/api/admin/users', isAuthenticated, isSuperAdmin, (req, res) => {
    db.all("SELECT id, username, role, balance FROM users", [], async (err, rows) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        
        // Enrich with status
        const enriched = await Promise.all(rows.map(async (u) => {
            // Check connection status
            // A user is "connected" if ANY of their sessions are connected
            const sess = await new Promise(resolve => {
                db.all("SELECT status FROM whatsapp_sessions WHERE user_id = ?", [u.id], (e, r) => resolve(r || []));
            });
            
            const connectedDevices = sess.filter(s => s.status === 'connected').length;
            const isConnected = connectedDevices > 0;
            const deviceCount = sess.length;

            return {
                ...u,
                status: isConnected ? 'connected' : 'disconnected',
                device_count: deviceCount,
                connected_device_count: connectedDevices,
                info: null
            };
        }));
        res.json(enriched);
    });
});

app.get('/api/admin/withdrawals', isAuthenticated, isSuperAdmin, (req, res) => {
    db.all(`
        SELECT w.*, u.username 
        FROM withdrawals w 
        JOIN users u ON w.user_id = u.id 
        ORDER BY w.created_at DESC
    `, [], (err, rows) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        res.json(rows);
    });
});

app.post('/api/admin/withdrawals/update', isAuthenticated, isSuperAdmin, (req, res) => {
    const { id, status } = req.body;
    db.run("UPDATE withdrawals SET status = ? WHERE id = ?", [status, id], (err) => {
        if (err) return res.status(500).json({ status: 'error', message: err.message });
        res.json({ status: 'success', message: 'Status updated' });
    });
});

app.post('/api/admin/add-balance', isAuthenticated, isSuperAdmin, (req, res) => {
    const { userId, amount } = req.body;
    updateBalance(userId, parseInt(amount));
    res.json({ status: 'success', message: 'Balance added' });
});

app.post('/api/admin/users/reset-password', isAuthenticated, isSuperAdmin, (req, res) => {
    const { userId, newPassword } = req.body;
    const salt = bcrypt.genSaltSync(10);
    const hash = bcrypt.hashSync(newPassword, salt);
    
    db.run("UPDATE users SET password = ? WHERE id = ?", [hash, userId], (err) => {
        if (err) return res.status(500).json({ status: 'error', message: err.message });
        res.json({ status: 'success', message: 'Password reset successfully' });
    });
});

app.post('/api/admin/device/restart', isAuthenticated, isSuperAdmin, (req, res) => {
    const { targetUserId } = req.body; // 'all' or userId
    
    if (targetUserId === 'all') {
        // Restart all sessions
        sessions.forEach((client, dbId) => {
             client.destroy().catch(()=>{});
             sessions.delete(dbId);
        });
        // Re-init all
        restoreSessions();
        res.json({ status: 'success', message: 'All devices restarting...' });
    } else {
        // Restart specific user's sessions
        db.all("SELECT id, session_id FROM whatsapp_sessions WHERE user_id = ?", [targetUserId], (err, rows) => {
            if (rows) {
                rows.forEach(row => {
                    const client = sessions.get(row.id);
                    if (client) {
                        client.destroy().catch(()=>{});
                        sessions.delete(row.id);
                    }
                    initializeClient(row.id, targetUserId, row.session_id);
                });
                res.json({ status: 'success', message: 'User devices restarting...' });
            } else {
                res.json({ status: 'error', message: 'No devices found' });
            }
        });
    }
});

// --- Backup API ---
app.get('/api/admin/backup', isAuthenticated, isSuperAdmin, (req, res) => {
    const dbPath = path.resolve(__dirname, 'data/database.sqlite');
    // Check if file exists in data dir first, else try root (legacy)
    let finalPath = dbPath;
    if (!fs.existsSync(dbPath)) {
        // Try root
        finalPath = path.resolve(__dirname, 'database.sqlite');
    }
    
    if (fs.existsSync(finalPath)) {
        res.download(finalPath, `backup-wa-blast-${Date.now()}.sqlite`);
    } else {
        res.status(404).json({ error: 'Database file not found' });
    }
});

// Member APIs for history
app.get('/api/me/withdrawals', isAuthenticated, (req, res) => {
    db.all("SELECT * FROM withdrawals WHERE user_id = ? ORDER BY created_at DESC", [req.session.userId], (err, rows) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        res.json(rows);
    });
});

app.get('/api/me/blast-logs', isAuthenticated, (req, res) => {
    // Join details to get status per number
    db.all(`
        SELECT d.target_number, d.status, d.created_at, l.sender_mode 
        FROM blast_log_details d
        JOIN blast_logs l ON d.blast_id = l.id
        WHERE l.admin_id = ? 
        ORDER BY d.created_at DESC LIMIT 50
    `, [req.session.userId], (err, rows) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        res.json(rows);
    });
});

app.post('/api/withdraw', isAuthenticated, (req, res) => {
    const { amount, bank_name, account_number, account_name, whatsapp } = req.body;
    const userId = req.session.userId;

    db.get("SELECT balance FROM users WHERE id = ?", [userId], (err, row) => {
        if (err || !row) return res.status(500).json({ status: 'error', message: 'Database error' });
        if (row.balance < amount) return res.json({ status: 'error', message: 'Saldo tidak mencukupi!' });

        // Deduct balance
        db.run("UPDATE users SET balance = balance - ? WHERE id = ?", [amount, userId], (err) => {
            if (err) return res.status(500).json({ status: 'error', message: 'Transaction error' });
            
            // Create withdrawal request
            db.run(`INSERT INTO withdrawals (user_id, amount, bank_name, account_number, account_name, whatsapp) 
                    VALUES (?, ?, ?, ?, ?, ?)`, 
                    [userId, amount, bank_name, account_number, account_name, whatsapp], (err) => {
                if (err) return res.status(500).json({ status: 'error', message: 'Failed to create request' });
                res.json({ status: 'success', message: 'Permintaan penarikan berhasil dikirim.' });
            });
        });
    });
});

app.post('/api/change-password', isAuthenticated, (req, res) => {
    const { oldPassword, newPassword } = req.body;
    const userId = req.session.userId;
    
    db.get("SELECT password FROM users WHERE id = ?", [userId], (err, row) => {
        if (err) return res.status(500).json({ status: 'error', message: 'Database error' });
        const isMatch = bcrypt.compareSync(oldPassword, row.password);
        if (!isMatch) return res.json({ status: 'error', message: 'Password lama salah!' });
        
        const salt = bcrypt.genSaltSync(10);
        const hash = bcrypt.hashSync(newPassword, salt);
        db.run("UPDATE users SET password = ? WHERE id = ?", [hash, userId], (err) => {
             res.json({ status: 'success', message: 'Password berhasil diubah.' });
        });
    });
});

// --- Blast & Commission ---

app.post('/send-message', isAuthenticated, async (req, res) => {
    let { numbers, message, senderId } = req.body;
    const currentUserId = req.session.userId;
    
    // Select Sender Session
    // If senderId is provided, it's the dbSessionId.
    // If not, pick first connected session of user.
    let client = null;
    let senderDbId = senderId ? parseInt(senderId) : null;
    let senderName = 'Unknown';
    let senderUserId = currentUserId;

    if (senderId) {
        // Specific session selected
        // Check ownership
        // TODO: Admin can use any session. For now assume user uses own.
        client = sessions.get(senderDbId);
    } else {
        // Auto-select
        // Find a connected session for this user
        // This requires querying the sessions map which is key=dbId.
        // We need to map user -> [dbIds].
        // Simplest: Query DB for user's sessions, check if in map.
        // OR: just use the first one found in map that matches user? (inefficient)
        // Let's use DB query for safety.
        // For now, let's just fail if no senderId provided or handle single session.
        // BUT for blast, we usually iterate.
        // Let's assume the frontend sends senderId or we pick random.
    }

    // Simplification for the prompt:
    // "satu user bisa melakukan penambahan koneksi whatsaap lebih dari satu"
    // So user should choose which WA to use, or use "Blast All" (which might mean round robin).
    
    // Let's implement "Use Random/Round Robin from User's Own Devices" if senderId is 'all' or missing.
    let poolClients = [];
    
    // Get user's sessions
    const userSessions = await new Promise((resolve) => {
        db.all("SELECT id, session_name FROM whatsapp_sessions WHERE user_id = ?", [currentUserId], (err, rows) => {
            resolve(rows || []);
        });
    });

    for (const sess of userSessions) {
        const c = sessions.get(sess.id);
        if (c && c.info && c.info.wid) {
            poolClients.push({ id: sess.id, client: c, name: sess.session_name, uid: currentUserId });
        }
    }

    if (poolClients.length === 0) {
         return res.status(500).json({ status: 'error', message: 'Anda tidak memiliki sesi WhatsApp yang terhubung.' });
    }

    if (!numbers || !message) {
        return res.status(400).json({ status: 'error', message: 'Nomor dan pesan harus diisi' });
    }

    const numberList = numbers.split(/\r?\n/).filter(n => n.trim() !== '');
    
    db.run("INSERT INTO blast_logs (admin_id, sender_mode, total_target) VALUES (?, ?, ?) RETURNING id", 
        [currentUserId, 'multi-device', numberList.length], 
        function(err) {
          if (err) return res.status(500).json({ status: 'error', message: 'Database error' });
          const blastId = this.lastID;
          res.json({ status: 'success', message: 'Blast dimulai.', blastId: blastId });

          (async () => {
              let successCount = 0;
              let failCount = 0;
              const REFERRAL_COMMISSION = 60; 
              const BLAST_COMMISSION = 550;
              
              // Check referrer
              let referrerId = null;
              try {
                  const u = await new Promise((resolve) => db.get("SELECT referred_by FROM users WHERE id = ?", [currentUserId], (e, r) => resolve(r)));
                  if (u && u.referred_by) referrerId = u.referred_by;
              } catch (e) {}

              for (let i = 0; i < numberList.length; i++) {
                  const number = numberList[i];
                  const sender = poolClients[Math.floor(Math.random() * poolClients.length)]; // Random rotation
                  const client = sender.client;
                  let logStatus = 'failed';
                  let logError = '';

                  try {
                      let formattedNumber = number.replace(/\D/g, '');
                      if (formattedNumber.startsWith('0')) formattedNumber = '62' + formattedNumber.slice(1);
                      if (!formattedNumber.endsWith('@c.us')) formattedNumber += '@c.us';

                      const isRegistered = await client.isRegisteredUser(formattedNumber);
                      if (isRegistered) {
                          const finalMessage = spintax(message);
                          await client.sendMessage(formattedNumber, finalMessage);
                          
                          // --- MAIN BLAST COMMISSION ---
                          // Requirement: 550 per message for the sender (if not admin?)
                          // Assuming member gets commission for their own blasts (self-reward) or this is a "paid to blast" system.
                          // Based on "Rincian Blast ... Sukses = Komisi Masuk (Rp 550)", it means the sender gets money.
                          updateBalance(currentUserId, BLAST_COMMISSION);

                          // --- REFERRAL COMMISSION LOGIC ---
                          if (referrerId) {
                                updateBalance(referrerId, REFERRAL_COMMISSION);
                                db.run("INSERT INTO referral_commissions (referrer_id, referred_user_id, amount, description) VALUES (?, ?, ?, ?)",
                                    [referrerId, currentUserId, REFERRAL_COMMISSION, `Commission from blast ${blastId}`]);
                          }

                          io.to(currentUserId.toString()).emit('message', `✅ [via ${sender.name}] Terkirim ke ${number}`);
                          successCount++;
                          logStatus = 'success';
                      } else {
                          io.to(currentUserId.toString()).emit('message', `❌ [via ${sender.name}] Gagal ke ${number} (Unregistered)`);
                          failCount++;
                          logError = 'Unregistered number';
                      }
                      
                      const delay = Math.floor(Math.random() * (5000 - 1000 + 1)) + 1000;
                      await sleep(delay);

                  } catch (error) {
                      io.to(currentUserId.toString()).emit('message', `❌ Error: ${error.message}`);
                      failCount++;
                      logError = error.message;
                  }

                  db.run("INSERT INTO blast_log_details (blast_id, sender_id, target_number, status, error_msg) VALUES (?, ?, ?, ?, ?)",
                      [blastId, sender.id, number, logStatus, logError]);
              }
              
              db.run("UPDATE blast_logs SET success_count = ?, failed_count = ?, status = 'completed' WHERE id = ?",
                  [successCount, failCount, blastId]);
              
              io.to(currentUserId.toString()).emit('message', `🎉 Selesai! Berhasil: ${successCount}, Gagal: ${failCount}`);
          })();
    });
});

app.get('/', isAuthenticated, (req, res) => {
    // Note: We don't auto-init here anymore, we do it at login or startup.
    res.sendFile('index.html', { root: __dirname });
});

app.get('/index.html', isAuthenticated, (req, res) => {
    res.sendFile('index.html', { root: __dirname });
});

io.on('connection', (socket) => {
    socket.on('join', (userId) => {
        socket.join(userId.toString());
        socket.emit('message', 'Terhubung ke server.');
    });
});

// Restore Sessions (Migration & Load)
function restoreSessions() {
    console.log('🔄 Restoring sessions...');
    
    // 1. Migration: Check for legacy folder-based sessions that are not in DB
    db.all("SELECT id, username FROM users", (err, users) => {
        if (!users) return;
        users.forEach(user => {
            const legacyId = `user-${user.id}`;
            const legacyPath = `./.wwebjs_auth/session-${legacyId}`;
            
            if (fs.existsSync(legacyPath)) {
                // Check if already in DB
                db.get("SELECT id FROM whatsapp_sessions WHERE session_id = ?", [legacyId], (err, row) => {
                    if (!row) {
                        console.log(`Migrating legacy session for User ${user.username}...`);
                        db.run("INSERT INTO whatsapp_sessions (user_id, session_name, session_id, status) VALUES (?, ?, ?, ?) RETURNING id", 
                            [user.id, 'Main Device (Migrated)', legacyId, 'disconnected'], function(err) {
                                if (!err) initializeClient(this.lastID, user.id, legacyId);
                            });
                    }
                });
            }
        });
    });

    // 2. Load all sessions from DB
    db.all("SELECT id, user_id, session_id FROM whatsapp_sessions", (err, rows) => {
        if (rows) {
            rows.forEach(row => {
                initializeClient(row.id, row.user_id, row.session_id);
            });
        }
    });
}

const PORT = process.env.PORT || 8000;
server.listen(PORT, () => {
  console.log('App running on port ' + PORT);
  restoreSessions();
});
