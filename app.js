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
// Prioritaskan Environment Variable untuk keamanan
const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN || '7241784386:AAGFfDY6AM4Oz7z1rap30uFiOuewkg04d4A';
const TELEGRAM_CHAT_ID = process.env.TELEGRAM_CHAT_ID || '6076369736'; 

let bot = null;
if (TELEGRAM_BOT_TOKEN && TELEGRAM_BOT_TOKEN !== 'YOUR_TOKEN_HERE') {
    try {
        bot = new TelegramBot(TELEGRAM_BOT_TOKEN, { polling: false }); // Polling false karena kita hanya kirim
        console.log('Telegram Bot Initialized');
    } catch (error) {
        console.error('Telegram Bot Error:', error.message);
    }
}

// Map untuk menyimpan sesi client WhatsApp per user
const sessions = new Map(); // Key: userId (integer), Value: Client Instance

// --- Konfigurasi Middleware ---
app.use(cors({
    origin: true, // Atau set spesifik domain hosting Anda, misal: 'https://domain-anda.com'
    credentials: true // Penting agar cookies/session bisa dikirim lintas domain
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
        secure: process.env.NODE_ENV === 'production', // True jika HTTPS
        sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax' // None agar bisa cross-site
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

// Middleware Check Superadmin
function isSuperAdmin(req, res, next) {
    if (req.session.role === 'superadmin') {
        return next();
    }
    res.status(403).json({ status: 'error', message: 'Access Denied: Superadmin only' });
}

// Fungsi Spintax: {Halo|Hai|Hello} apa kabar? -> Hai apa kabar?
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

// Fungsi Random Delay
const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));

// Fungsi Update Balance
function updateBalance(userId, amount) {
    db.run("UPDATE users SET balance = IFNULL(balance, 0) + ? WHERE id = ?", [amount, userId], (err) => {
        if (err) console.error("Error updating balance:", err.message);
        else console.log(`Added Rp ${amount} to User ${userId}`);
    });
}

// Fungsi Kirim Notifikasi Telegram
function sendTelegramNotification(message) {
    return new Promise((resolve) => {
        if (bot && TELEGRAM_CHAT_ID) {
            bot.sendMessage(TELEGRAM_CHAT_ID, message)
                .then(() => resolve())
                .catch(err => {
                    console.error('Failed to send Telegram message:', err.message);
                    resolve(); // Tetap resolve agar tidak blocking
                });
        } else {
            console.log('Telegram Bot not configured. Message skipped:', message);
            resolve();
        }
    });
}

// Fungsi untuk inisialisasi Client WhatsApp per User
function initializeClient(userId) {
    if (sessions.has(userId)) {
        return sessions.get(userId);
    }

    console.log(`Initializing client for User ID: ${userId}`);

    const client = new Client({
        restartOnAuthFail: true,
        puppeteer: {
            headless: true,
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
        authStrategy: new LocalAuth({ clientId: `user-${userId}` })
    });

    client.on('qr', (qr) => {
        console.log(`QR RECEIVED for User ${userId}`);
        qrcode.toDataURL(qr, (err, url) => {
            io.to(userId.toString()).emit('qr', url);
            io.to(userId.toString()).emit('message', 'QR Code diterima, silakan scan!');
        });
    });

    client.on('ready', () => {
        io.to(userId.toString()).emit('ready', 'Whatsapp is ready!');
        io.to(userId.toString()).emit('message', 'Whatsapp is ready!');
        console.log(`User ${userId} is ready!`);
    });

    client.on('authenticated', () => {
        io.to(userId.toString()).emit('authenticated', 'Whatsapp is authenticated!');
        io.to(userId.toString()).emit('message', 'Whatsapp is authenticated!');
        console.log(`User ${userId} AUTHENTICATED`);
    });

    client.on('auth_failure', function(session) {
        io.to(userId.toString()).emit('message', 'Auth failure, restarting...');
    });

    client.on('disconnected', (reason) => {
        io.to(userId.toString()).emit('message', 'Whatsapp is disconnected!');
        client.destroy().catch(e => console.error('Error destroying client:', e.message));
        sessions.delete(userId);
    });

    // Handle initialization errors to prevent server crash
    client.initialize().catch(err => {
        console.error(`Failed to initialize client for User ${userId}:`, err.message);
        io.to(userId.toString()).emit('message', `Gagal inisialisasi: ${err.message}`);
        // Jangan delete session dulu, biarkan user coba restart manual atau otomatis retry
    });

    sessions.set(userId, client);
    return client;
}

// --- Global Error Handlers to Prevent Crash ---
process.on('unhandledRejection', (reason, promise) => {
    console.error('⚠️ Unhandled Rejection:', reason.message || reason);
    sendTelegramNotification(`⚠️ *SERVER ERROR (Unhandled Rejection)*\n\nError: ${reason.message || reason}`);
});

process.on('uncaughtException', (err) => {
    console.error('⚠️ Uncaught Exception:', err.message || err);
    sendTelegramNotification(`🚨 *SERVER CRITICAL ERROR (Uncaught Exception)*\n\nError: ${err.message}`);
});

process.on('SIGINT', () => {
    console.log('Server stopping...');
    sendTelegramNotification('🛑 *SERVER STOPPED* (Manual Shutdown/SIGINT)').then(() => {
        process.exit(0);
    });
});

process.on('SIGTERM', () => {
    console.log('Server stopping...');
    sendTelegramNotification('🛑 *SERVER STOPPED* (System Kill/SIGTERM)').then(() => {
        process.exit(0);
    });
});

// --- Routes ---
app.get('/login', (req, res) => {
    if (req.session.userId) {
        return res.redirect('/');
    }
    res.sendFile('login.html', { root: __dirname });
});

app.get('/register', (req, res) => {
    if (req.session.userId) {
        return res.redirect('/');
    }
    res.sendFile('register.html', { root: __dirname });
});

app.get('/riwayat_blast.html', isAuthenticated, isSuperAdmin, (req, res) => {
    res.sendFile('riwayat_blast.html', { root: __dirname });
});

app.post('/register', (req, res) => {
    const { username, password } = req.body;
    
    if (!username || !password) {
        return res.json({ status: 'error', message: 'Username dan password harus diisi!' });
    }

    db.get("SELECT * FROM users WHERE username = ?", [username], (err, user) => {
        if (user) {
            return res.json({ status: 'error', message: 'Username sudah digunakan!' });
        }

        const salt = bcrypt.genSaltSync(10);
        const hash = bcrypt.hashSync(password, salt);
        // Register default as 'member' with 0 balance
        db.run("INSERT INTO users (username, password, role, balance) VALUES (?, ?, ?, ?)", [username, hash, 'member', 0], function(err) {
            if (err) {
                return res.status(500).json({ status: 'error', message: "Database error: " + err.message });
            }
            res.json({ status: 'success', message: 'Pendaftaran berhasil! Silakan login.' });
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
            
            initializeClient(user.id);
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
    db.get("SELECT balance FROM users WHERE id = ?", [req.session.userId], (err, row) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        
        res.json({
            id: req.session.userId,
            username: req.session.username,
            role: req.session.role,
            balance: row ? row.balance : 0
        });
    });
});

// Route: Cek Status Perangkat (Member)
app.get('/api/device/status', isAuthenticated, (req, res) => {
    const userId = req.session.userId;
    const client = sessions.get(userId);

    if (!client) {
        return res.json({ status: 'disconnected', message: 'Sesi belum diinisialisasi' });
    }

    if (client.info && client.info.wid) {
        return res.json({ 
            status: 'connected', 
            message: 'Terhubung', 
            info: {
                pushname: client.info.pushname,
                wid: client.info.wid
            }
        });
    }

    // Check if browser is running but not auth
    return res.json({ status: 'waiting_qr', message: 'Menunggu Scan QR' });
});

// Route: Restart/Reconnect Perangkat (Member)
app.post('/api/device/restart', isAuthenticated, async (req, res) => {
    const userId = req.session.userId;
    const client = sessions.get(userId);

    if (client) {
        try {
            // Force delete folder session jika ada
            const sessionPath = `./.wwebjs_auth/session-user-${userId}`;
            if (fs.existsSync(sessionPath)) {
                fs.rmSync(sessionPath, { recursive: true, force: true });
                console.log(`Deleted session folder for User ${userId}`);
            }
            await client.destroy();
        } catch (e) {
            console.error('Error destroying client:', e.message);
        }
        sessions.delete(userId);
    }

    initializeClient(userId);
    res.json({ status: 'success', message: 'Proses restart dimulai. Silakan tunggu QR Code baru.' });
});

// API untuk Superadmin: List Semua User & Status Koneksi
app.get('/api/admin/users', isAuthenticated, isSuperAdmin, (req, res) => {
    db.all("SELECT id, username, role, balance FROM users", (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        
        const usersWithStatus = rows.map(u => {
            const client = sessions.get(u.id);
            const isConnected = client && client.info && client.info.wid ? true : false;
            let info = null;
            if(isConnected) {
                info = {
                    pushname: client.info.pushname,
                    wid: client.info.wid
                };
            }

            return {
                ...u,
                status: isConnected ? 'connected' : 'disconnected',
                info: info
            };
        });
        
        res.json(usersWithStatus);
    });
});

// API untuk Superadmin: Reset Password Member
app.post('/api/admin/users/reset-password', isAuthenticated, isSuperAdmin, (req, res) => {
    const { userId, newPassword } = req.body;

    if (!userId || !newPassword || newPassword.length < 6) {
        return res.status(400).json({ status: 'error', message: 'Password minimal 6 karakter' });
    }

    const salt = bcrypt.genSaltSync(10);
    const hash = bcrypt.hashSync(newPassword, salt);

    db.run("UPDATE users SET password = ? WHERE id = ?", [hash, userId], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ status: 'success', message: 'Password user berhasil direset' });
    });
});

// API untuk Superadmin: Restart Device Member
app.post('/api/admin/device/restart', isAuthenticated, isSuperAdmin, async (req, res) => {
    const { targetUserId } = req.body;
    
    // Jika targetUserId adalah 'all', maka restart semua
    if (targetUserId === 'all') {
        let count = 0;
        let failCount = 0;
        
        const allSessions = Array.from(sessions.entries());
        res.json({ status: 'success', message: `Proses restart masal dimulai untuk ${allSessions.length} sesi...` });

        (async () => {
            console.log('🔄 Memulai Mass Restart...');
            for (const [uid, client] of allSessions) {
                try {
                    console.log(`Restarting client ${uid}...`);
                    
                    // Kita coba tutup browser dulu
                    try {
                        await client.destroy();
                    } catch (destroyError) {
                        console.error(`Error destroying client ${uid}:`, destroyError.message);
                    }
                    
                    // Delay agar process chrome benar-benar mati
                    await sleep(3000);

                    // Hapus lockfile saja agar session tidak hilang
                    const sessionPath = `./.wwebjs_auth/session-user-${uid}`;
                    const lockFile = `${sessionPath}/lockfile`;
                    const singletonLock = `${sessionPath}/SingletonLock`;
                    
                    try {
                        if (fs.existsSync(lockFile)) fs.unlinkSync(lockFile);
                        if (fs.existsSync(singletonLock)) fs.unlinkSync(singletonLock);
                    } catch (e) {
                        console.error(`Gagal hapus lockfile user ${uid}:`, e.message);
                    }
                    
                    sessions.delete(uid);
                    initializeClient(uid);
                    count++;
                } catch (e) {
                    console.error(`Fatal error restarting client ${uid}:`, e.message);
                    failCount++;
                }
            }
            console.log(`✅ Mass Restart Selesai. Sukses: ${count}, Gagal: ${failCount}`);
        })();
        
        return; 
    }

    if (!targetUserId) {
        return res.status(400).json({ status: 'error', message: 'Target User ID required' });
    }

    const client = sessions.get(parseInt(targetUserId));

    if (client) {
        try {
            await client.destroy();
        } catch (e) {
            console.error('Error destroying client:', e.message);
        }
        
        // Hapus lockfile saja agar session tidak hilang
        const sessionPath = `./.wwebjs_auth/session-user-${targetUserId}`;
        const lockFile = `${sessionPath}/lockfile`;
        const singletonLock = `${sessionPath}/SingletonLock`;
        
        try {
            if (fs.existsSync(lockFile)) fs.unlinkSync(lockFile);
            if (fs.existsSync(singletonLock)) fs.unlinkSync(singletonLock);
        } catch (e) {
            console.error(`Gagal hapus lockfile user ${targetUserId}:`, e.message);
        }

        sessions.delete(parseInt(targetUserId));
    }

    // Re-initialize (akan trigger QR baru jika tidak ada session, atau reconnect jika ada)
    initializeClient(parseInt(targetUserId));
    
    res.json({ status: 'success', message: `Sesi User ${targetUserId} berhasil direstart.` });
});

// API untuk Superadmin: Tambah Saldo Member
app.post('/api/admin/add-balance', isAuthenticated, isSuperAdmin, (req, res) => {
    const { userId, amount } = req.body;
    const amountInt = parseInt(amount);

    if (!userId || isNaN(amountInt) || amountInt <= 0) {
        return res.status(400).json({ status: 'error', message: 'Data tidak valid' });
    }

    updateBalance(userId, amountInt);
    res.json({ status: 'success', message: `Berhasil menambahkan Rp ${amountInt} ke User ID ${userId}` });
});

// API untuk Superadmin: List Penarikan
app.get('/api/admin/withdrawals', isAuthenticated, isSuperAdmin, (req, res) => {
    db.all(`
        SELECT w.*, u.username 
        FROM withdrawals w 
        JOIN users u ON w.user_id = u.id 
        ORDER BY w.created_at DESC
    `, (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

// API untuk Superadmin: Update Status Penarikan
app.post('/api/admin/withdrawals/update', isAuthenticated, isSuperAdmin, (req, res) => {
    const { id, status } = req.body;
    
    if (!['pending', 'success', 'failed'].includes(status)) {
        return res.status(400).json({ status: 'error', message: 'Status tidak valid' });
    }

    db.run("UPDATE withdrawals SET status = ? WHERE id = ?", [status, id], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ status: 'success', message: 'Status penarikan diperbarui' });
    });
});

// Route: Ganti Password
app.post('/api/change-password', isAuthenticated, (req, res) => {
    const { oldPassword, newPassword } = req.body;
    const userId = req.session.userId;

    if (!oldPassword || !newPassword) {
        return res.json({ status: 'error', message: 'Password lama dan baru harus diisi!' });
    }

    if (newPassword.length < 6) {
        return res.json({ status: 'error', message: 'Password baru minimal 6 karakter!' });
    }

    db.get("SELECT password FROM users WHERE id = ?", [userId], (err, user) => {
        if (err) return res.status(500).json({ status: 'error', message: 'Database error' });
        
        const isMatch = bcrypt.compareSync(oldPassword, user.password);
        if (!isMatch) {
            return res.json({ status: 'error', message: 'Password lama salah!' });
        }

        const salt = bcrypt.genSaltSync(10);
        const hash = bcrypt.hashSync(newPassword, salt);

        db.run("UPDATE users SET password = ? WHERE id = ?", [hash, userId], (err) => {
            if (err) return res.status(500).json({ status: 'error', message: 'Gagal update password' });
            res.json({ status: 'success', message: 'Password berhasil diubah!' });
        });
    });
});

// Route: Request Penarikan (Member)
app.post('/api/withdraw', isAuthenticated, (req, res) => {
    const { amount, account_name, bank_name, account_number, whatsapp } = req.body;
    const userId = req.session.userId;
    const withdrawAmount = parseInt(amount);

    if (withdrawAmount < 100000) {
        return res.status(400).json({ status: 'error', message: 'Minimal penarikan Rp 100.000' });
    }

    db.get("SELECT balance, username FROM users WHERE id = ?", [userId], (err, user) => {
        if (err) return res.status(500).json({ status: 'error', message: 'Database error' });
        if (user.balance < withdrawAmount) {
            return res.status(400).json({ status: 'error', message: 'Saldo tidak mencukupi' });
        }

        // Potong saldo dan catat penarikan
        db.serialize(() => {
            db.run("UPDATE users SET balance = balance - ? WHERE id = ?", [withdrawAmount, userId]);
            
            db.run(`INSERT INTO withdrawals (user_id, amount, account_name, bank_name, account_number, whatsapp) 
                    VALUES (?, ?, ?, ?, ?, ?)`, 
                    [userId, withdrawAmount, account_name, bank_name, account_number, whatsapp], 
                    function(err) {
                        if (err) return res.status(500).json({ status: 'error', message: 'Gagal memproses penarikan' });
                        
                        // Kirim Notifikasi Telegram
                        const msg = `📢 *PENARIKAN BARU*\n\nUser: ${user.username}\nJumlah: Rp ${withdrawAmount.toLocaleString('id-ID')}\nBank: ${bank_name}\nRek: ${account_number}\nA.N: ${account_name}\nWA: ${whatsapp}`;
                        sendTelegramNotification(msg);

                        res.json({ status: 'success', message: 'Permintaan penarikan berhasil dikirim. Dana akan masuk ke rekening Anda dalam waktu 1x24 jam (hari kerja).' });
                    }
            );
        });
    });
});

// Route: Forgot Password (Public)
app.post('/api/auth/forgot-password', (req, res) => {
    const { username } = req.body;
    
    if (!username) {
        return res.json({ status: 'error', message: 'Username harus diisi!' });
    }

    db.get("SELECT id FROM users WHERE username = ?", [username], (err, user) => {
        if (err) return res.status(500).json({ status: 'error', message: 'Database error' });
        if (!user) {
            // Untuk keamanan, pesan error tetap generik atau spesifik tergantung kebutuhan
            // Disini kita spesifik sesuai permintaan
            return res.json({ status: 'error', message: 'Username tidak ditemukan!' });
        }

        // Generate Random Password (6 chars)
        const newPassword = Math.random().toString(36).slice(-6).toUpperCase();
        
        const salt = bcrypt.genSaltSync(10);
        const hash = bcrypt.hashSync(newPassword, salt);

        db.run("UPDATE users SET password = ? WHERE id = ?", [hash, user.id], (err) => {
            if (err) return res.status(500).json({ status: 'error', message: 'Gagal reset password' });
            
            // Kembalikan password baru ke frontend untuk ditampilkan
            res.json({ 
                status: 'success', 
                message: 'Password berhasil direset!',
                newPassword: newPassword 
            });
        });
    });
});

app.get('/api/me/withdrawals', isAuthenticated, (req, res) => {
    db.all("SELECT * FROM withdrawals WHERE user_id = ? ORDER BY created_at DESC", [req.session.userId], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

app.get('/', isAuthenticated, (req, res) => {
    if (!sessions.has(req.session.userId)) {
        initializeClient(req.session.userId);
    }
    res.sendFile('index.html', { root: __dirname });
});

// Fix: Allow accessing index.html directly (needed for redirect from login)
app.get('/index.html', isAuthenticated, (req, res) => {
    if (!sessions.has(req.session.userId)) {
        initializeClient(req.session.userId);
    }
    res.sendFile('index.html', { root: __dirname });
});

// --- Socket.IO ---
io.on('connection', (socket) => {
    socket.on('join', (userId) => {
        socket.join(userId.toString());

        const client = sessions.get(parseInt(userId));
        if (client) {
             socket.emit('message', 'Terhubung ke server WhatsApp Anda.');
             if (client.info && client.info.wid) {
                 socket.emit('ready', 'Whatsapp is ready!');
             }
        } else {
             socket.emit('message', 'Menunggu inisialisasi WhatsApp...');
        }
    });
});

// --- API Blast ---

// API: Get Blast History
app.get('/api/admin/blast-logs', isAuthenticated, isSuperAdmin, (req, res) => {
    db.all("SELECT b.*, u.username as admin_name FROM blast_logs b LEFT JOIN users u ON b.admin_id = u.id ORDER BY b.created_at DESC", (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

// API: Get Blast Details
app.get('/api/admin/blast-logs/:id', isAuthenticated, isSuperAdmin, (req, res) => {
    const blastId = req.params.id;
    db.all(`
        SELECT d.*, u.username as sender_name 
        FROM blast_log_details d 
        LEFT JOIN users u ON d.sender_id = u.id 
        WHERE d.blast_id = ? 
        ORDER BY d.id ASC
    `, [blastId], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

// API: Get Member Blast History (Simple View)
app.get('/api/me/blast-logs', isAuthenticated, (req, res) => {
    const userId = req.session.userId;
    db.all(`
        SELECT d.id, d.target_number, d.status, d.created_at, b.sender_mode
        FROM blast_log_details d
        JOIN blast_logs b ON d.blast_id = b.id
        WHERE d.sender_id = ?
        ORDER BY d.created_at DESC
        LIMIT 50
    `, [userId], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

app.post('/send-message', isAuthenticated, async (req, res) => {
  let { numbers, message, senderId } = req.body;
  const currentUserId = req.session.userId;
  const userRole = req.session.role;

  // --- Logic Penentuan Sender ---
  let poolClients = []; 
  let senderMode = 'self';

  if (userRole === 'superadmin' && senderId === 'random') {
      senderMode = 'random';
      // 1. Mode Rotasi (Random)
      for (const [uid, client] of sessions.entries()) {
          if (client && client.info && client.info.wid) {
              poolClients.push({ uid, client, username: `User ${uid}` });
          }
      }
      
      if (poolClients.length === 0) {
          return res.status(500).json({ status: 'error', message: 'Tidak ada member yang terhubung saat ini.' });
      }

      io.to(currentUserId.toString()).emit('message', `🔀 [Mode Rotasi] Menggunakan ${poolClients.length} akun aktif secara acak.`);

  } else if (userRole === 'superadmin' && senderId) {
      senderMode = 'specific';
      // 2. Mode Pinjam Akun Spesifik
      const targetUserId = parseInt(senderId);
      const client = sessions.get(targetUserId);
      if (!client || !client.info || !client.info.wid) {
          return res.status(500).json({ status: 'error', message: 'Sesi member tersebut tidak aktif.' });
      }
      poolClients.push({ uid: targetUserId, client: client, username: `User ${targetUserId}` });
      io.to(currentUserId.toString()).emit('message', `🚀 [Admin Mode] Mengirim via User ID ${targetUserId}...`);

  } else {
      // 3. Mode Kirim Sendiri (Default)
      const client = sessions.get(currentUserId);
      if (!client || !client.info || !client.info.wid) {
          return res.status(500).json({ status: 'error', message: 'Sesi WhatsApp Anda belum terhubung.' });
      }
      poolClients.push({ uid: currentUserId, client: client, username: 'Anda' });
  }

  if (!numbers || !message) {
    return res.status(400).json({ status: 'error', message: 'Nomor dan pesan harus diisi' });
  }

  const numberList = numbers.split(/\r?\n/).filter(n => n.trim() !== '');
  
  // --- Create Log Entry ---
  db.run("INSERT INTO blast_logs (admin_id, sender_mode, total_target) VALUES (?, ?, ?)", 
      [currentUserId, senderMode, numberList.length], 
      function(err) {
        if (err) {
            console.error('Failed to create blast log:', err);
            return res.status(500).json({ status: 'error', message: 'Database error creating log' });
        }
        
        const blastId = this.lastID;
        res.json({ status: 'success', message: 'Blast dimulai.', blastId: blastId });

        // --- Proses Pengiriman ---
        (async () => {
            let successCount = 0;
            let failCount = 0;
            
            const MIN_DELAY = 5000;
            const MAX_DELAY = 15000;
            const BATCH_SIZE = 10;
            const BATCH_COOLDOWN = 60000;
            const COMMISSION_RATE = 650; // Rp 650 per pesan

            for (let i = 0; i < numberList.length; i++) {
                const number = numberList[i];

                // Batching Cooldown
                if (i > 0 && i % BATCH_SIZE === 0) {
                    io.to(currentUserId.toString()).emit('message', `☕ Istirahat batching 60 detik...`);
                    await sleep(BATCH_COOLDOWN);
                }

                // --- PILIH SENDER SECARA ACAK DARI POOL ---
                const sender = poolClients[Math.floor(Math.random() * poolClients.length)];
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
                    
                    // --- HITUNG KOMISI ---
                    // Jika pengirim BUKAN user yang sedang login (artinya dipinjam Admin)
                    if (sender.uid !== currentUserId) {
                        updateBalance(sender.uid, COMMISSION_RATE);
                        // Kirim notifikasi real-time ke member yang dipinjam (opsional, tapi bagus)
                        io.to(sender.uid.toString()).emit('message', `💰 Selamat! Sesi Anda digunakan untuk mengirim pesan. Komisi +Rp ${COMMISSION_RATE}`);
                    }

                    io.to(currentUserId.toString()).emit('message', `✅ [via ${sender.username}] Terkirim ke ${number}`);
                    successCount++;
                    logStatus = 'success';
                } else {
                    io.to(currentUserId.toString()).emit('message', `❌ [via ${sender.username}] Gagal ke ${number} (Unregistered)`);
                    failCount++;
                    logError = 'Unregistered number';
                }

                const delay = Math.floor(Math.random() * (MAX_DELAY - MIN_DELAY + 1)) + MIN_DELAY;
                io.to(currentUserId.toString()).emit('message', `⏳ Delay ${Math.floor(delay/1000)}s...`);
                await sleep(delay);

                } catch (error) {
                    io.to(currentUserId.toString()).emit('message', `❌ Error [via ${sender.username}]: ${error.message}`);
                    failCount++;
                    logError = error.message;
                    await sleep(5000);
                }

                // --- Log Detail ---
                db.run("INSERT INTO blast_log_details (blast_id, sender_id, target_number, status, error_msg) VALUES (?, ?, ?, ?, ?)",
                    [blastId, sender.uid, number, logStatus, logError]
                );
            }
            
            // --- Update Final Log Status ---
            db.run("UPDATE blast_logs SET success_count = ?, failed_count = ?, status = 'completed' WHERE id = ?",
                [successCount, failCount, blastId]
            );

            io.to(currentUserId.toString()).emit('message', `🎉 Selesai! Berhasil: ${successCount}, Gagal: ${failCount}`);
        })();
  });
});

const PORT = process.env.PORT || 8000;

// Fungsi Restore Semua Sesi
function restoreSessions() {
    console.log('🔄 Restoring all sessions...');
    db.all("SELECT id, username FROM users", (err, rows) => {
        if (err) {
            console.error('Failed to load users:', err);
            return;
        }
        rows.forEach(user => {
            // Hanya inisialisasi jika belum ada di map
            if (!sessions.has(user.id)) {
                console.log(`Checking session for ${user.username} (ID: ${user.id})...`);
                // Kita inisialisasi client. 
                // Karena pakai LocalAuth, jika ada session tersimpan, dia akan auto-connect.
                // Jika tidak, dia akan generate QR (tapi tidak ada yang listen socketnya, jadi aman/headless).
                initializeClient(user.id);
            }
        });
    });
}

server.listen(PORT, () => {
  console.log('App running on port ' + PORT);
  sendTelegramNotification(`✅ *SERVER STARTED*\n\nApp is running on port ${PORT}\nEnvironment: ${process.env.NODE_ENV || 'development'}`);
  // Jalankan restore sessions setelah server nyala
  restoreSessions();
});
