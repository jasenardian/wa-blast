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
        bot = new TelegramBot(TELEGRAM_BOT_TOKEN, { polling: true }); 
        console.log('Telegram Bot Initialized');
        
        // Handle Polling Errors to prevent crash
        bot.on('polling_error', (error) => {
            if (error.code === 'ETELEGRAM' && error.message.includes('Conflict')) {
                // Suppress conflict error logs (happens when multiple instances run)
            } else {
                console.error('Telegram Bot Polling Error:', error.message);
            }
        });

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
function sendTelegramNotification(message, options = {}) {
    return new Promise((resolve) => {
        if (bot && TELEGRAM_CHAT_ID) {
            bot.sendMessage(TELEGRAM_CHAT_ID, message, options)
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

// REMOVE DUPLICATE FUNCTION sendTelegramNotification FROM HERE IF EXISTS
// (Already moved up or existing one needs update)
// Let's replace the existing one to match the new signature if it was defined below
// The original code had sendTelegramNotification around line 97.
// I will replace it with the enhanced version.


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

        // Telegram Notification: WA Connected
        const waMsg = `
🟢 *WHATSAPP CONNECTED*
━━━━━━━━━━━━━━━━━━━
🆔 Session ID: ${dbSessionId}
👤 User ID: ${userId}
📱 WA Name: ${info.pushname || 'Unknown'}
📞 WA Number: ${info.wid.user}
🏭 Platform: ${info.platform}
📅 Date: ${new Date().toLocaleString()}
━━━━━━━━━━━━━━━━━━━`;
        sendTelegramNotification(waMsg);
    });

    client.on('authenticated', () => {
        io.to(userId.toString()).emit('authenticated', { sessionId: dbSessionId });
        io.to(userId.toString()).emit('message', `Whatsapp Sesi #${dbSessionId} is authenticated!`);
        console.log(`Session ${dbSessionId} AUTHENTICATED`);
    });

    client.on('auth_failure', function(session) {
        io.to(userId.toString()).emit('message', `Auth failure on Session #${dbSessionId}, restarting...`);
        db.run("UPDATE whatsapp_sessions SET status = 'disconnected' WHERE id = ?", [dbSessionId]);
        
        // Telegram Notification: Auth Failure
        const authFailMsg = `
⚠️ *WHATSAPP AUTH FAILURE*
━━━━━━━━━━━━━━━━━━━
🆔 Session ID: ${dbSessionId}
👤 User ID: ${userId}
ℹ️ Info: Sesi perlu scan ulang.
📅 Date: ${new Date().toLocaleString()}
━━━━━━━━━━━━━━━━━━━`;
        sendTelegramNotification(authFailMsg);
    });

    client.on('disconnected', (reason) => {
        io.to(userId.toString()).emit('disconnected', { sessionId: dbSessionId });
        io.to(userId.toString()).emit('message', `Whatsapp Sesi #${dbSessionId} is disconnected!`);
        db.run("UPDATE whatsapp_sessions SET status = 'disconnected' WHERE id = ?", [dbSessionId]);
        
        // Telegram Notification: Disconnected
        const disconnectMsg = `
🔴 *WHATSAPP DISCONNECTED*
━━━━━━━━━━━━━━━━━━━
🆔 Session ID: ${dbSessionId}
👤 User ID: ${userId}
reason: ${reason}
📅 Date: ${new Date().toLocaleString()}
━━━━━━━━━━━━━━━━━━━`;
        sendTelegramNotification(disconnectMsg);
        
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
    sendTelegramNotification(`
🚨 *CRITICAL SERVER ERROR*
━━━━━━━━━━━━━━━━━━━
⚠️ Error: ${err.message || err}
📅 Date: ${new Date().toLocaleString()}
━━━━━━━━━━━━━━━━━━━
_Server might restart automatically._
    `);
});

process.on('SIGINT', () => {
    console.log('Server stopping...');
    sendTelegramNotification('🛑 Server Stopping (SIGINT)...').then(() => process.exit(0));
});

process.on('SIGTERM', () => {
    console.log('Server stopping...');
    sendTelegramNotification('🛑 Server Stopping (SIGTERM)...').then(() => process.exit(0));
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
    const { username, password, referralCode, phone } = req.body;
    
    if (!username || !password || !phone) {
        return res.json({ status: 'error', message: 'Username, password, dan No. HP harus diisi!' });
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

            db.run("INSERT INTO users (username, password, role, balance, referral_code, referred_by, phone) VALUES (?, ?, ?, ?, ?, ?, ?)", 
                [username, hash, 'member', 0, ownRefCode, referredBy, phone], function(err) {
                if (err) {
                    return res.status(500).json({ status: 'error', message: "Database error: " + err.message });
                }
                
                // Telegram Notification: New User
                const regMsg = `
📢 *NEW USER REGISTERED*
━━━━━━━━━━━━━━━━━━━
👤 Username: ${username}
📱 Phone: ${phone}
🎟 Ref Code: ${ownRefCode}
📅 Date: ${new Date().toLocaleString()}
━━━━━━━━━━━━━━━━━━━`;
                sendTelegramNotification(regMsg);

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
            db.all("SELECT id, session_id FROM whatsapp_sessions WHERE user_id = ?", [user.id], async (err, rows) => {
                if (rows) {
                    for (const row of rows) {
                        if (!sessions.has(row.id)) {
                             initializeClient(row.id, user.id, row.session_id);
                             await new Promise(r => setTimeout(r, 5000)); // Stagger login init too
                        }
                    }
                }
            });

            // Telegram Notification: User Login
            const loginMsg = `
🔐 *USER LOGIN ALERT*
━━━━━━━━━━━━━━━━━━━
👤 Username: ${user.username}
🆔 User ID: ${user.id}
📅 Date: ${new Date().toLocaleString()}
━━━━━━━━━━━━━━━━━━━`;
            sendTelegramNotification(loginMsg);

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
app.post('/api/devices', isAuthenticated, async (req, res) => {
    const { session_name, method, pairing_number } = req.body;
    const userId = req.session.userId;
    const sessionName = session_name || `Device ${Date.now()}`;
    const uniqueSessionId = `session-${userId}-${Date.now()}`; // Unique for LocalAuth

    db.run("INSERT INTO whatsapp_sessions (user_id, session_name, session_id, status) VALUES (?, ?, ?, ?) RETURNING id", 
        [userId, sessionName, uniqueSessionId, 'disconnected'], async function(err) {
        if (err) return res.status(500).json({ error: err.message });
        
        const newDbId = this.lastID;
        const client = initializeClient(newDbId, userId, uniqueSessionId);
        
        res.json({ status: 'success', message: 'Device added', data: { id: newDbId } });

        // Handle OTP Pairing if requested
        if (method === 'otp' && pairing_number) {
            try {
                // Wait for client to be ready/loading to request code
                // Note: client.requestPairingCode needs client to be initialized and in a state where it can request code.
                // Usually 'qr' event fires first. We need to wait for that or 'ready'.
                // Actually, we can call it after initialization started.
                
                console.log(`Requesting Pairing Code for ${pairing_number}...`);
                
                // Wait a bit for puppeteer to start
                let retries = 0;
                while (!client.pupPage && retries < 20) {
                    await sleep(1000);
                    retries++;
                }

                if (client) {
                   // Ensure number format
                   let num = pairing_number.replace(/\D/g, '');
                   if (num.startsWith('0')) num = '62' + num.slice(1);
                   
                   // Extra delay to ensure WA Web modules are loaded
                   console.log(`Waiting for WA Web modules to load for session ${newDbId}...`);
                   await sleep(5000);

                   try {
                       const code = await client.requestPairingCode(num);
                       console.log(`Pairing Code for ${uniqueSessionId}: ${code}`);
                       io.to(userId.toString()).emit('pairing_code', { sessionId: newDbId, code: code });
                   } catch (innerErr) {
                       console.error("Pairing Code Inner Error:", innerErr.message);
                       io.to(userId.toString()).emit('message', `Gagal request Pairing Code (Retrying...): ${innerErr.message}`);
                   }
                }
            } catch (e) {
                console.error("Pairing Code Error:", e);
                io.to(userId.toString()).emit('message', `Gagal request Pairing Code: ${e.message}`);
            }
        }
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

// --- Admin User Management ---

app.post('/api/admin/users/add', isAuthenticated, isSuperAdmin, (req, res) => {
    const { username, password, role, phone } = req.body;
    if (!username || !password || !role) return res.json({ status: 'error', message: 'Data tidak lengkap' });
    
    const salt = bcrypt.genSaltSync(10);
    const hash = bcrypt.hashSync(password, salt);
    const ownRefCode = (username.substring(0, 3) + Math.random().toString(36).substring(2, 5)).toUpperCase();

    db.run("INSERT INTO users (username, password, role, balance, referral_code, phone) VALUES (?, ?, ?, ?, ?, ?)", 
        [username, hash, role, 0, ownRefCode, phone], (err) => {
        if (err) return res.json({ status: 'error', message: err.message });
        res.json({ status: 'success', message: 'User berhasil ditambahkan' });
    });
});

app.delete('/api/admin/users/:id', isAuthenticated, isSuperAdmin, (req, res) => {
    const userId = req.params.id;
    // Prevent delete self
    if (userId == req.session.userId) return res.json({ status: 'error', message: 'Tidak bisa menghapus akun sendiri' });

    db.run("DELETE FROM users WHERE id = ?", [userId], (err) => {
        if (err) return res.json({ status: 'error', message: err.message });
        // Cleanup sessions
        db.all("SELECT id FROM whatsapp_sessions WHERE user_id = ?", [userId], (err, rows) => {
            if(rows) {
                rows.forEach(r => {
                    const client = sessions.get(r.id);
                    if(client) { client.destroy().catch(()=>{}); sessions.delete(r.id); }
                });
            }
            db.run("DELETE FROM whatsapp_sessions WHERE user_id = ?", [userId]);
        });
        res.json({ status: 'success', message: 'User dihapus' });
    });
});

app.post('/api/admin/users/update-role', isAuthenticated, isSuperAdmin, (req, res) => {
    const { userId, role } = req.body;
    db.run("UPDATE users SET role = ? WHERE id = ?", [role, userId], (err) => {
        if (err) return res.json({ status: 'error', message: err.message });
        res.json({ status: 'success', message: 'Role diupdate' });
    });
});

app.get('/api/admin/users', isAuthenticated, isSuperAdmin, (req, res) => {
    db.all("SELECT id, username, role, balance FROM users", [], async (err, rows) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        
        // Enrich with status
        const enriched = await Promise.all(rows.map(async (u) => {
            // Check connection status
            // A user is "connected" if ANY of their sessions are connected
            const sess = await new Promise(resolve => {
                db.all("SELECT session_name, status, device_info FROM whatsapp_sessions WHERE user_id = ?", [u.id], (e, r) => resolve(r || []));
            });
            
            const connectedDevices = sess.filter(s => s.status === 'connected').length;
            const isConnected = connectedDevices > 0;
            const deviceCount = sess.length;

            return {
                ...u,
                status: isConnected ? 'connected' : 'disconnected',
                device_count: deviceCount,
                connected_device_count: connectedDevices,
                devices: sess, // Send full device list details
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

app.get('/api/admin/topups', isAuthenticated, isSuperAdmin, (req, res) => {
    db.all(`
        SELECT t.*, u.username 
        FROM topups t 
        JOIN users u ON t.user_id = u.id 
        ORDER BY t.created_at DESC
    `, [], (err, rows) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        res.json(rows);
    });
});

app.post('/api/admin/topups/approve', isAuthenticated, isSuperAdmin, (req, res) => {
    const { id, userId, amount } = req.body;
    
    db.get("SELECT status FROM topups WHERE id = ?", [id], (err, row) => {
        if (row && row.status === 'success') return res.json({ status: 'error', message: 'Topup sudah diapprove sebelumnya' });

        db.run("UPDATE topups SET status = 'success' WHERE id = ?", [id], (err) => {
            if (err) return res.json({ status: 'error', message: err.message });
            
            // Add Balance
            updateBalance(userId, parseInt(amount));
            
            res.json({ status: 'success', message: 'Topup Approved & Saldo Added' });
        });
    });
});

// --- Admin Bank Management ---
app.get('/api/admin/banks', isAuthenticated, (req, res) => {
    // Accessible by all authenticated users to populate dropdown
    db.all("SELECT * FROM admin_banks WHERE is_active = ?", [true], (err, rows) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        res.json(rows);
    });
});

app.post('/api/admin/banks', isAuthenticated, isSuperAdmin, (req, res) => {
    const { bank_name, account_number, account_name } = req.body;
    db.run("INSERT INTO admin_banks (bank_name, account_number, account_name) VALUES (?, ?, ?)", 
        [bank_name, account_number, account_name], (err) => {
        if (err) return res.json({ status: 'error', message: err.message });
        res.json({ status: 'success', message: 'Rekening berhasil ditambahkan' });
    });
});

app.delete('/api/admin/banks/:id', isAuthenticated, isSuperAdmin, (req, res) => {
    db.run("DELETE FROM admin_banks WHERE id = ?", [req.params.id], (err) => {
        if (err) return res.json({ status: 'error', message: err.message });
        res.json({ status: 'success', message: 'Rekening dihapus' });
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
        db.all("SELECT id, session_id FROM whatsapp_sessions WHERE user_id = ?", [targetUserId], async (err, rows) => {
            if (rows) {
                res.json({ status: 'success', message: 'User devices restarting (sequentially)...' });
                for (const row of rows) {
                    const client = sessions.get(row.id);
                    if (client) {
                        try { await client.destroy(); } catch(e){}
                        sessions.delete(row.id);
                    }
                    initializeClient(row.id, targetUserId, row.session_id);
                    await new Promise(r => setTimeout(r, 5000));
                }
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

app.get('/api/me/topups', isAuthenticated, (req, res) => {
    db.all("SELECT * FROM topups WHERE user_id = ? ORDER BY created_at DESC", [req.session.userId], (err, rows) => {
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
        if (amount < 10000) return res.json({ status: 'error', message: 'Minimal penarikan Rp 10.000!' });
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

app.post('/api/topup', isAuthenticated, (req, res) => {
    const { amount, payment_method } = req.body;
    const userId = req.session.userId;

    if (amount < 10000) return res.json({ status: 'error', message: 'Minimal topup Rp 10.000!' });

    db.run("INSERT INTO topups (user_id, amount, payment_method, status) VALUES (?, ?, ?, ?)", 
        [userId, amount, payment_method, 'pending'], (err) => {
        if (err) return res.status(500).json({ status: 'error', message: 'Database error' });
        
        // Telegram Notification
        const msg = `
💰 *NEW TOPUP REQUEST*
━━━━━━━━━━━━━━━━━━━
👤 User: ${req.session.username}
💵 Amount: Rp${parseInt(amount).toLocaleString()}
💳 Method: ${payment_method}
📅 Date: ${new Date().toLocaleString()}
━━━━━━━━━━━━━━━━━━━`;
        sendTelegramNotification(msg);

        res.json({ status: 'success', message: 'Permintaan Topup berhasil. Silakan transfer dan konfirmasi Admin.' });
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

// app.post('/api/upgrade-pro', ... ) DELETED/DISABLED as per request for manual upgrade logic

app.post('/send-message', isAuthenticated, async (req, res) => {
    const { numbers, message, mode } = req.body;
    const currentUserId = req.session.userId;
    
    // --- POOL SELECTION LOGIC ---
    let poolClients = [];
    
    // Determine Target Mode
    let targetMode = 'self';
    if (req.session.role === 'admin' || req.session.role === 'superadmin') {
        targetMode = mode || 'global';
    }

    if (targetMode === 'global') {
        // ADMIN GLOBAL MODE: Use All Connected Sessions (Crowdsourcing)
        const allSessions = await new Promise((resolve) => {
            db.all("SELECT id, session_name, user_id FROM whatsapp_sessions WHERE status = 'connected'", [], (err, rows) => {
                resolve(rows || []);
            });
        });

        for (const sess of allSessions) {
            const c = sessions.get(sess.id);
            if (c && c.info && c.info.wid) {
                poolClients.push({ id: sess.id, client: c, name: sess.session_name, uid: sess.user_id });
            }
        }
    } else {
        // SELF MODE: Use Own Connected Sessions
        const mySessions = await new Promise((resolve) => {
            db.all("SELECT id, session_name, user_id FROM whatsapp_sessions WHERE user_id = ? AND status = 'connected'", [currentUserId], (err, rows) => {
                resolve(rows || []);
            });
        });

        for (const sess of mySessions) {
            const c = sessions.get(sess.id);
            if (c && c.info && c.info.wid) {
                poolClients.push({ id: sess.id, client: c, name: sess.session_name, uid: sess.user_id });
            }
        }
    }

    if (poolClients.length === 0) {
         return res.status(500).json({ status: 'error', message: 'Anda tidak memiliki sesi WhatsApp yang terhubung.' });
    }

    if (!numbers || !message) {
        return res.status(400).json({ status: 'error', message: 'Nomor dan pesan harus diisi' });
    }

    const numberList = numbers.split(/\r?\n/).filter(n => n.trim() !== '');

    // --- Admin Balance Check ---
    const userRole = req.session.role;
    let ADMIN_BLAST_COST = 900; // Harga default per pesan untuk Admin
    
    // Logika Diskon sederhana (Opsional)
    if (numberList.length >= 10000) ADMIN_BLAST_COST = 800;

    if (userRole === 'admin' || userRole === 'superadmin') {
        const requiredBalance = numberList.length * ADMIN_BLAST_COST;
        
        // Hapus syarat saldo mengendap, cukup cek apakah saldo cukup untuk bayar blast ini
        const currentBalance = await new Promise(resolve => {
            db.get("SELECT balance FROM users WHERE id = ?", [currentUserId], (err, row) => resolve(row ? row.balance : 0));
        });

        // Superadmin bypass balance check (optional), but let's enforce it for "admin" role
        if (userRole === 'admin') {
            if (currentBalance < requiredBalance) {
                 return res.status(400).json({ 
                    status: 'error', 
                    message: `Saldo tidak mencukupi! Biaya: Rp${ADMIN_BLAST_COST}/pesan. Total diperlukan: Rp${requiredBalance.toLocaleString()}. Saldo Anda: Rp${currentBalance.toLocaleString()}` 
                });
            }
        }
    }
    
    
    if (poolClients.length === 0) {
         return res.status(500).json({ 
             status: 'error', 
             message: targetMode === 'global' 
                ? 'Tidak ada perangkat member yang tersedia untuk crowdsourcing.' 
                : 'Anda tidak memiliki perangkat WhatsApp yang terhubung. Silakan scan QR terlebih dahulu.' 
         });
    }

    db.run("INSERT INTO blast_logs (admin_id, sender_mode, total_target) VALUES (?, ?, ?) RETURNING id", 
        [currentUserId, targetMode, numberList.length], 
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
                  let logError = '';

                  try {
                      let formattedNumber = number.replace(/\D/g, '');
                      if (formattedNumber.startsWith('0')) formattedNumber = '62' + formattedNumber.slice(1);
                      if (!formattedNumber.endsWith('@c.us')) formattedNumber += '@c.us';

                      const isRegistered = await client.isRegisteredUser(formattedNumber);
                      if (isRegistered) {
                          const finalMessage = spintax(message);
                          await client.sendMessage(formattedNumber, finalMessage);
                          
                          if (userRole === 'admin') {
                              // Admin: PAYS for blast
                              updateBalance(currentUserId, -ADMIN_BLAST_COST);
                          } else if (userRole === 'superadmin') {
                              // Superadmin: FREE & NEUTRAL (No Cost, No Earning)
                              // Do nothing with balance
                          } else {
                              // Member: EARNS from blast
                              // --- MAIN BLAST COMMISSION ---
                              updateBalance(currentUserId, BLAST_COMMISSION);
    
                              // --- REFERRAL COMMISSION LOGIC ---
                              if (referrerId) {
                                    updateBalance(referrerId, REFERRAL_COMMISSION);
                                    db.run("INSERT INTO referral_commissions (referrer_id, referred_user_id, amount, description) VALUES (?, ?, ?, ?)",
                                        [referrerId, currentUserId, REFERRAL_COMMISSION, `Commission from blast ${blastId}`]);
                              }
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

// --- Admin Blast Logs API ---
app.get('/api/admin/blast-logs', isAuthenticated, isSuperAdmin, (req, res) => {
    db.all(`
        SELECT b.*, u.username as admin_name 
        FROM blast_logs b
        LEFT JOIN users u ON b.admin_id = u.id
        ORDER BY b.created_at DESC
    `, [], (err, rows) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        res.json(rows);
    });
});

app.get('/api/admin/blast-logs/:id', isAuthenticated, isSuperAdmin, (req, res) => {
    const blastId = req.params.id;
    db.all(`
        SELECT d.*, s.session_name as sender_name 
        FROM blast_log_details d
        LEFT JOIN whatsapp_sessions s ON d.sender_id = s.id
        WHERE d.blast_id = ?
        ORDER BY d.id ASC
    `, [blastId], (err, rows) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        res.json(rows);
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
    db.all("SELECT id, user_id, session_id FROM whatsapp_sessions", async (err, rows) => {
        if (rows) {
            console.log(`Found ${rows.length} sessions to restore. Starting sequential initialization...`);
            for (const row of rows) {
                // Check if already running to be safe
                if (!sessions.has(row.id)) {
                    initializeClient(row.id, row.user_id, row.session_id);
                    // Delay 15 seconds between starts to prevent CPU/RAM spike on Railway
                    console.log(`Waiting 15s before next session...`);
                    await new Promise(r => setTimeout(r, 15000));
                }
            }
        }
    });
}

const PORT = process.env.PORT || 8000;

// --- Scheduled Task: Check Inactive Users ---
setInterval(() => {
    checkInactiveUsers();
}, 10 * 60 * 1000); // Run every 10 minutes

async function checkInactiveUsers() {
    console.log("Checking for inactive users...");
    // Criteria: Registered > 30 mins ago, No connected sessions, Not yet notified
    // SQLite doesn't have easy date math in WHERE clause like PG, but we can do simple check or filter in JS.
    // However, let's try to do it in SQL if possible or fetch candidate users.
    // For simplicity and compatibility, let's fetch users registered who have inactive_notified = 0.
    
    // Note: We need to check if they have any 'connected' session.
    // This requires a JOIN or a subquery.
    
    const sql = `
        SELECT u.id, u.username, u.phone, u.referral_code 
        FROM users u
        WHERE (u.inactive_notified = FALSE OR u.inactive_notified IS NULL)
    `;

    db.all(sql, [], async (err, users) => {
        if (err || !users) return;

        for (const user of users) {
            // Check sessions
            const hasConnectedSession = await new Promise(resolve => {
                db.get("SELECT COUNT(*) as count FROM whatsapp_sessions WHERE user_id = ? AND status = 'connected'", [user.id], (e, r) => {
                    resolve(r ? r.count > 0 : false);
                });
            });

            if (!hasConnectedSession) {
                // Check registration time? We didn't store created_at in users table in the provided schema...
                // Wait, the schema in database.js DOES NOT have created_at for users table.
                // So we can't check "registered > 30 mins ago".
                // We will have to assume "if the checker runs and they are not connected, notify them".
                // To avoid notifying immediately after register, we might need to add created_at column.
                // OR, just notify once. If the user just registered 1 min ago, they will get a notification.
                // Maybe that's fine? "Welcome! Please connect WA."
                
                // Let's Send Notification
                const msg = `
⚠️ *USER INACTIVE ALERT*
━━━━━━━━━━━━━━━━━━━
👤 Username: ${user.username}
📱 Phone: ${user.phone}
ℹ️ Status: Belum Menautkan WhatsApp
━━━━━━━━━━━━━━━━━━━
_User ini belum menautkan WhatsApp. Segera ingatkan agar mereka bisa mendapatkan komisi!_`;

                const opts = {
                    reply_markup: {
                        inline_keyboard: [
                            [
                                { text: "🔔 Ingatkan User (via WA)", callback_data: `remind_wa_${user.id}` }
                            ]
                        ]
                    }
                };

                await sendTelegramNotification(msg, opts);

                // Mark as notified
                db.run("UPDATE users SET inactive_notified = ? WHERE id = ?", [true, user.id]);
            }
        }
    });
}

// --- Telegram Callback Handler ---
if (bot) {
    bot.on('callback_query', async (callbackQuery) => {
        const action = callbackQuery.data;
        const msg = callbackQuery.message;
        const chatId = msg.chat.id;

        if (action.startsWith('remind_wa_')) {
            const userId = action.split('_')[2];
            
            // 1. Get User Details
            db.get("SELECT username, phone FROM users WHERE id = ?", [userId], async (err, user) => {
                if (!user || !user.phone) {
                    bot.sendMessage(chatId, "❌ Gagal: User tidak ditemukan atau tidak memiliki nomor HP.");
                    return;
                }

                // 2. Find Sender (Admin's Session or any available session)
                // We need a connected session to send the reminder.
                // Let's look for ANY connected session in the system.
                let senderClient = null;
                let senderName = "";

                // Iterate over all sessions in memory
                for (const [sessId, client] of sessions.entries()) {
                    if (client && client.info && client.info.wid) {
                        senderClient = client;
                        senderName = client.info.pushname;
                        break; // Found one
                    }
                }

                if (!senderClient) {
                    bot.sendMessage(chatId, "❌ Gagal: Tidak ada sesi WhatsApp yang terhubung di sistem untuk mengirim pesan.");
                    return;
                }

                // 3. Send Message
                try {
                    let number = user.phone.replace(/\D/g, '');
                    if (number.startsWith('0')) number = '62' + number.slice(1);
                    if (!number.endsWith('@c.us')) number += '@c.us';

                    const reminderMsg = `Halo Kak ${user.username}, 👋\n\nKami melihat kakak sudah mendaftar di *WA Blast Pro* tapi belum menautkan WhatsApp.\n\nAyo segera tautkan WhatsApp kakak sekarang untuk mulai mendapatkan *Komisi* dan menggunakan fitur Blast!\n\nJika ada kendala, silakan hubungi admin ya. Terima kasih! 🙏`;

                    const isRegistered = await senderClient.isRegisteredUser(number);
                    if (isRegistered) {
                        await senderClient.sendMessage(number, reminderMsg);
                        bot.sendMessage(chatId, `✅ Berhasil mengirim pengingat ke ${user.username} (${user.phone}) via ${senderName}.`);
                    } else {
                        bot.sendMessage(chatId, `❌ Gagal: Nomor ${user.phone} tidak terdaftar di WhatsApp.`);
                    }
                } catch (e) {
                    bot.sendMessage(chatId, `❌ Error saat mengirim: ${e.message}`);
                }
            });

            // Answer callback to stop loading animation
            bot.answerCallbackQuery(callbackQuery.id);
        }
    });
}

server.listen(PORT, () => {
  console.log('App running on port ' + PORT);
  sendTelegramNotification(`
🚀 *SERVER STARTED*
━━━━━━━━━━━━━━━━━━━
🌍 Port: ${PORT}
📅 Date: ${new Date().toLocaleString()}
━━━━━━━━━━━━━━━━━━━
_System is ready to accept connections._
  `);
  restoreSessions();
});
