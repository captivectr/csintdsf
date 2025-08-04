const express = require('express');
const axios = require('axios');
const session = require('express-session');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const crypto = require('crypto');
const multer = require('multer');
const fs = require('fs');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const hpp = require('hpp');
const xss = require('xss-clean');
const mongoSanitize = require('express-mongo-sanitize');
const validator = require('validator');
const csrf = require('csurf');
const cookieParser = require('cookie-parser');
const compression = require('compression');
const cors = require('cors');
require('dotenv').config();
const fetch = require('node-fetch'); // Add at the top if not already present


const app = express();
const server = require('http').createServer(app);
const wss = new (require('ws').Server)({ server });
const PORT = process.env.PORT || 7261;
const CSINT_BASE_URL="https://csint.tools";
const CSINT_API_KEY = process.env.CSINT_API_KEY || "848914919401-priv";
    
const db = new sqlite3.Database('intelsec.db');

app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://cdn.tailwindcss.com", "https://fonts.googleapis.com"],
            scriptSrc: ["'self'", "'unsafe-inline'", "https://cdn.tailwindcss.com", "https://unpkg.com"],
            fontSrc: ["'self'", "https://fonts.gstatic.com"],
            imgSrc: ["'self'", "data:", "https:"],
            connectSrc: ["'self'", "wss:", "ws:"],
            frameSrc: ["'none'"],
            objectSrc: ["'none'"],
            upgradeInsecureRequests: []
        }
    },
    hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
    },
    noSniff: true,
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' }
}));

const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, 
    max: 100, 
    handler: (req, res) => res.render('ratelimit'),
    standardHeaders: true,
    legacyHeaders: false,
});

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, 
    max: 5, 
    handler: (req, res) => res.render('ratelimit'),
    standardHeaders: true,
    legacyHeaders: false,
});

const searchLimiter = rateLimit({
    windowMs: 60 * 1000, 
    max: 10, 
    handler: (req, res) => res.render('ratelimit'),
    standardHeaders: true,
    legacyHeaders: false,
});


app.use(limiter);
app.use('/login', authLimiter);
app.use('/search', searchLimiter);

app.use(hpp()); 
app.use(xss()); 
app.use(mongoSanitize()); 
app.use(compression()); 
app.use(cors({
    origin: process.env.NODE_ENV === 'production' ? ['https://intelsec.cc'] : true,
    credentials: true
}));

const upload = multer({
    dest: path.join(__dirname, 'public/uploads'),
    limits: {
        fileSize: 5 * 1024 * 1024, 
        files: 1
    },
    fileFilter: (req, file, cb) => {
        if (file.mimetype.startsWith('image/')) {
            cb(null, true);
        } else {
            cb(new Error('Only image files are allowed!'), false);
        }
    }
});

wss.on('connection', (ws, req) => {
    console.log('New WebSocket connection established');
    
    ws.on('message', (message) => {
        try {
            const data = JSON.parse(message.toString());
            console.log('WebSocket message received:', data);
            if (data.type === 'auth' && data.username) {
                connectedClients.set(data.username, ws);
                console.log(`User ${data.username} authenticated via WebSocket`);
            }
        } catch (err) {
            console.log('WebSocket message parsing error:', err);
        }
    });
    
    ws.on('close', () => {
        for (const [username, client] of connectedClients.entries()) {
            if (client === ws) {
                connectedClients.delete(username);
                console.log(`User ${username} disconnected from WebSocket`);
                break;
            }
        }
    });
    
    ws.on('error', (error) => {
        console.log('WebSocket error:', error);
    });
});

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(express.json({ limit: '10mb' }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public'), {
    maxAge: '1d',
    etag: true,
    lastModified: true
}));

app.use(session({
    secret: process.env.SESSION_SECRET || crypto.randomBytes(64).toString('hex'),
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000, 
        sameSite: 'strict'
    },
    name: 'intelsec_session'
}));

function sanitizeInput(input) {
    if (typeof input !== 'string') return input;
    return validator.escape(validator.trim(input));
}

function validateUsername(username) {
    return validator.isAlphanumeric(username) && username.length >= 3 && username.length <= 20;
}

function validateQuery(query) {
    return validator.isLength(query, { min: 1, max: 500 }) && !validator.contains(query, '<script>');
}

function validateKey(key) {
    return validator.isNumeric(key) && key.length === 16;
}

function logSecurityEvent(event, details) {
    if (event.toLowerCase().includes('error') || event.toLowerCase().includes('fail')) {
        let msg = 'error:';
        if (typeof details === 'object' && details !== null) {
            if (details.error) msg += ' ' + details.error;
            else msg += ' ' + JSON.stringify(details);
        } else {
            msg += ' ' + details;
        }
        console.log(msg);
    }
}

function securityHeaders(req, res, next) {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
    next();
}

function validateSession(req, res, next) {
    if (!req.session || !req.session.user) {
        return res.status(401).json({ error: 'Unauthorized' });
    }
    
    if (req.session.cookie && req.session.cookie.expires && new Date() > req.session.cookie.expires) {
        req.session.destroy();
        return res.status(401).json({ error: 'Session expired' });
    }
    
    next();
}

function auditLog(req, res, next) {
    const originalSend = res.send;
    res.send = function(data) {
        logSecurityEvent('API_CALL', {
            method: req.method,
            path: req.path,
            ip: req.ip,
            userAgent: req.get('User-Agent'),
            statusCode: res.statusCode,
            timestamp: new Date().toISOString()
        });
        originalSend.call(this, data);
    };
    next();
}

app.use(securityHeaders);
app.use(auditLog);
db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        profile_pic TEXT
    )`);
    db.run(`CREATE TABLE IF NOT EXISTS keys (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        key TEXT UNIQUE,
        owner TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);
    db.get('SELECT * FROM users WHERE username = ?', ['admin'], (err, row) => {
        if (err) throw err;
        if (!row) {
            db.run('INSERT INTO users (username, password, is_admin, plan) VALUES (?, ?, ?, ?)', ['admin', 'admin', 1, 'lifetime'], function(err) {
                if (err) throw err;
                const adminKey = generateNumericKey();
                db.run('INSERT INTO keys (key, owner) VALUES (?, ?)', [adminKey, 'admin'], function(err) {
                    if (err) throw err;
                    console.log('Admin user created: admin/admin');
                    console.log('Admin key:', adminKey);
                });
            });
        } else {
            db.get('SELECT * FROM keys WHERE owner = ?', ['admin'], (err, keyRow) => {
                if (err) throw err;
                if (!keyRow) {
                    const adminKey = generateNumericKey();
                    db.run('INSERT INTO keys (key, owner) VALUES (?, ?)', [adminKey, 'admin'], function(err) {
                        if (err) throw err;
                        console.log('Admin key generated for existing admin:', adminKey);
                    });
                }
            });
            if (!row.plan) {
                db.run('UPDATE users SET plan = ? WHERE username = ?', ['lifetime', 'admin'], function(err) {
                    if (err) {
                        console.log('Error updating admin plan:', err);
                    } else {
                        console.log('Updated admin user plan to lifetime');
                    }
                });
            }
        }
    });
});

function addColumnIfNotExists(table, column, type, defaultValue) {
    db.all(`PRAGMA table_info(${table})`, (err, columns) => {
        if (err) return;
        const exists = Array.isArray(columns) && columns.some(col => col.name === column);
        if (!exists) {
            db.run(`ALTER TABLE ${table} ADD COLUMN ${column} ${type}${defaultValue !== undefined ? ' DEFAULT ' + defaultValue : ''}`);
        }
    });
}
addColumnIfNotExists('users', 'is_admin', 'INTEGER', 0);
addColumnIfNotExists('users', 'plan', 'TEXT', "'free'");
addColumnIfNotExists('users', 'banned', 'INTEGER', 0);
addColumnIfNotExists('users', 'rate_limited', 'INTEGER', 0);
addColumnIfNotExists('users', 'key_name', 'TEXT');
addColumnIfNotExists('users', 'plan_expires_at', 'DATETIME');
db.run(`CREATE TABLE IF NOT EXISTS announcements (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_user TEXT,
    message TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)`);

function setUserPlan(db, username, plan, cb) {
    let expires = null;
    if (plan === 'monthly') {
        expires = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();
    } else if (plan === 'yearly') {
        expires = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString();
    }
    db.run('UPDATE users SET plan = ?, plan_expires_at = ? WHERE username = ?', [plan, expires, username], cb);
}

db.get("PRAGMA table_info(announcements)", (err, rows) => {
    if (!err) {
        db.all("PRAGMA table_info(announcements)", (err, columns) => {
            if (!err) {
                const hasTargetKey = columns.some(col => col.name === 'target_key');
                const hasTargetUser = columns.some(col => col.name === 'target_user');
                
                if (hasTargetKey && !hasTargetUser) {
                    db.run("ALTER TABLE announcements RENAME COLUMN target_key TO target_user", (err) => {
                        if (err) console.log('Migration warning:', err.message);
                    });
                }
            }
        });
    }
});

function generateNumericKey() {
    let key = '';
    for (let i = 0; i < 16; i++) {
        key += Math.floor(Math.random() * 10);
    }
    return key;
}

(function backupDatabase() {
    const backupDir = path.join(__dirname, 'backups');
    if (!fs.existsSync(backupDir)) fs.mkdirSync(backupDir);
    const now = new Date();
    const pad = n => n.toString().padStart(2, '0');
    const timestamp = `${now.getFullYear()}${pad(now.getMonth()+1)}${pad(now.getDate())}-${pad(now.getHours())}${pad(now.getMinutes())}${pad(now.getSeconds())}`;
    const src = path.join(__dirname, 'intelsec.db');
    const dest = path.join(backupDir, `intelsec-${timestamp}.db`);
    if (fs.existsSync(src)) {
        fs.copyFileSync(src, dest);
    }
    const files = fs.readdirSync(backupDir).filter(f => f.startsWith('intelsec-') && f.endsWith('.db')).sort().reverse();
    files.slice(5).forEach(f => fs.unlinkSync(path.join(backupDir, f)));
})();

app.post('/generate-key', async (req, res) => {
    try {
        let key;
        let exists = true;
        while (exists) {
            key = Array.from({length: 16}, () => Math.floor(Math.random() * 10)).join('');
            exists = await new Promise(resolve => {
                db.get('SELECT 1 FROM keys WHERE key = ?', [key], (err, row) => {
                    resolve(!!row);
                });
            });
        }
        let guestUsername;
        let userExists = true;
        while (userExists) {
            guestUsername = 'newuser-' + Math.random().toString(36).substr(2, 8);
            userExists = await new Promise(resolve => {
                db.get('SELECT 1 FROM users WHERE username = ?', [guestUsername], (err, row) => {
                    resolve(!!row);
                });
            });
        }
        await new Promise((resolve, reject) => {
            db.run('INSERT INTO users (username, plan) VALUES (?, ?)', [guestUsername, 'free'], function(err) {
                if (err) return reject(err);
                resolve();
            });
        });
        await new Promise((resolve, reject) => {
            db.run('INSERT INTO keys (key, owner) VALUES (?, ?)', [key, guestUsername], function(err) {
                if (err) return reject(err);
                resolve();
            });
        });
        res.json({ success: true, key, username: guestUsername });
    } catch (err) {
        res.json({ success: false, error: err.message });
    }
});

const onlineUsers = new Set();
const connectedClients = new Map();
const searchStats = {
    searches: 0,
    failed: 0
};

function broadcastAnnouncement(announcement) {
    const message = JSON.stringify({
        type: 'announcement',
        data: announcement
    });
    
    console.log('Broadcasting announcement:', announcement);
    console.log('Connected clients:', connectedClients.size);
    
    if (announcement.target_user) {
        const targetClient = connectedClients.get(announcement.target_user);
        console.log(`Target user: ${announcement.target_user}, Client found: ${!!targetClient}`);
        if (targetClient && targetClient.readyState === 1) {
            targetClient.send(message);
            console.log(`Announcement sent to ${announcement.target_user}`);
        } else {
            console.log(`Target client not available or not ready for ${announcement.target_user}`);
        }
    } else {
        let sentCount = 0;
        connectedClients.forEach((client, username) => {
            if (client.readyState === 1) {
                client.send(message);
                sentCount++;
                console.log(`Announcement sent to ${username}`);
            } else {
                console.log(`Client ${username} not ready (state: ${client.readyState})`);
            }
        });
        console.log(`Broadcasted to ${sentCount} users`);
    }
}

db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS searches (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user TEXT,
        query TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);
});

app.post('/login', (req, res) => {
    const { username, password, key } = req.body;
    
    const sanitizedUsername = username ? sanitizeInput(username) : null;
    const sanitizedPassword = password ? sanitizeInput(password) : null;
    const sanitizedKey = key ? sanitizeInput(key) : null;
    
    logSecurityEvent('LOGIN_ATTEMPT', {
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        method: key ? 'key' : 'credentials',
        username: sanitizedUsername ? sanitizedUsername.substring(0, 3) + '***' : 'N/A'
    });
    
    if (sanitizedKey) {
        if (!validateKey(sanitizedKey)) {
            logSecurityEvent('INVALID_LOGIN_KEY', { ip: req.ip, keyPrefix: sanitizedKey.substring(0, 4) + '***' });
            return res.render('login', { error: 'Invalid key format.', message: undefined });
        }
        
        db.get('SELECT * FROM keys WHERE key = ?', [sanitizedKey], (err, keyRow) => {
            if (err) {
                logSecurityEvent('DB_ERROR', { operation: 'key_lookup', error: err.message });
                return res.render('login', { error: 'Database error.', message: undefined });
            }
            if (!keyRow) {
                logSecurityEvent('INVALID_KEY_LOGIN', { ip: req.ip, keyPrefix: sanitizedKey.substring(0, 4) + '***' });
                return res.render('login', { error: 'Invalid key.', message: undefined });
            }
            
            db.get('SELECT * FROM users WHERE username = ?', [keyRow.owner], (err, userRow) => {
                if (err || !userRow || !userRow.username) {
                    logSecurityEvent('USER_NOT_FOUND', { keyOwner: keyRow.owner });
                    return res.render('login', { error: 'User not found.', message: undefined });
                }
                if (userRow.banned) {
                    logSecurityEvent('BANNED_USER_LOGIN', { username: userRow.username });
                    return res.render('login', { error: 'Your account has been banned.', message: undefined });
                }
                
                req.session.user = {
                    username: userRow.username,
                    is_admin: !!userRow.is_admin,
                    plan: userRow.plan,
                    banned: !!userRow.banned,
                    rate_limited: !!userRow.rate_limited
                };
                onlineUsers.add(userRow.username);
                
                logSecurityEvent('SUCCESSFUL_LOGIN', { username: userRow.username, method: 'key' });
                return res.redirect('/dashboard');
            });
        });
    } else if (sanitizedUsername && sanitizedPassword) {
        if (!validateUsername(sanitizedUsername)) {
            logSecurityEvent('INVALID_USERNAME_LOGIN', { ip: req.ip, username: sanitizedUsername });
            return res.render('login', { error: 'Invalid username format.', message: undefined });
        }
        
        db.get('SELECT * FROM users WHERE username = ? AND password = ?', [sanitizedUsername, sanitizedPassword], (err, userRow) => {
            if (err) {
                logSecurityEvent('DB_ERROR', { operation: 'user_lookup', error: err.message });
                return res.render('login', { error: 'Database error.', message: undefined });
            }
            if (!userRow || !userRow.username) {
                logSecurityEvent('FAILED_LOGIN', { ip: req.ip, username: sanitizedUsername });
                return res.render('login', { error: 'Invalid credentials.', message: undefined });
            }
            if (userRow.banned) {
                logSecurityEvent('BANNED_USER_LOGIN', { username: userRow.username });
                return res.render('login', { error: 'Your account has been banned.', message: undefined });
            }
            
            req.session.user = {
                username: userRow.username,
                is_admin: !!userRow.is_admin,
                plan: userRow.plan,
                banned: !!userRow.banned,
                rate_limited: !!userRow.rate_limited
            };
            onlineUsers.add(userRow.username);
            
            logSecurityEvent('SUCCESSFUL_LOGIN', { username: userRow.username, method: 'credentials' });
            return res.redirect('/dashboard');
        });
    } else {
        logSecurityEvent('INCOMPLETE_LOGIN', { ip: req.ip });
        res.render('login', { error: 'Please provide credentials or a key.', message: undefined });
    }
});

app.get('/logout', (req, res) => {
    if (req.session.user) {
        onlineUsers.delete(req.session.user.username);
    }
    req.session.destroy(() => {
        res.redirect('/login');
    });
});

app.get('/login', (req, res) => {
    const error = req.query.error === 'banned' ? 'Your account has been banned.' : undefined;
    res.render('login', { error, message: undefined });
});

app.get('/', (req, res) => {
    res.render('home', { user: req.session.user });
});

app.get('/favicon.ico', (req, res) => {
    res.status(204).end(); 
});

const csintLimiter = rateLimit({
    windowMs: 60 * 1000, // 1 minute
    max: 5, // limit each IP to 5 requests per windowMs
    message: 'Too many CSINT API requests, please slow down.',
    standardHeaders: true,
    legacyHeaders: false,
});

function requireLogin(req, res, next) {
    if (!req.session.user || !req.session.user.username) return res.redirect('/login');
    if (req.session.user.banned) {
        req.session.destroy(() => {
            return res.redirect('/login?error=banned');
        });
        return;
    }
    next();
}

function requireAdmin(req, res, next) {
    if (!req.session.user || !req.session.user.is_admin) {
        return res.status(403).json({ error: 'Admin access required.' });
    }
    next();
}

app.get('/dashboard', requireLogin, (req, res) => {
    const username = req.session.user.username;
    
    if (req.session.user.rate_limited) {
        return res.render('dashboard', {
            user: req.session.user,
            searchCount: 0,
            recentSearches: [],
            onlineCount: onlineUsers.size,
            serverTime: new Date().toLocaleString(),
            profilePic: null,
            rateLimited: true,
            csrfToken: req.csrfToken ? req.csrfToken() : ''
        });
    }
    
    db.get('SELECT profile_pic FROM users WHERE username = ?', [username], (err, userRow) => {
        const profilePic = userRow && userRow.profile_pic ? '/uploads/' + userRow.profile_pic : null;
        db.all('SELECT query FROM searches WHERE user = ? ORDER BY timestamp DESC LIMIT 5', [username], (err, rows) => {
            const recentSearches = rows ? rows.map(r => r.query) : [];
            db.get('SELECT COUNT(*) as count FROM searches WHERE user = ?', [username], (err2, row2) => {
                const searchesCount = row2 ? row2.count : 0;
                const peopleOnline = onlineUsers.size;
                
                db.all('SELECT * FROM announcements WHERE target_user IS NULL OR target_user = ? ORDER BY created_at DESC', [username], (err3, announcements) => {
                    res.render('dashboard', {
                        user: req.session.user,
                        searchCount: searchesCount,
                        recentSearches,
                        onlineCount: peopleOnline,
                        serverTime: new Date().toLocaleString(),
                        profilePic,
                        announcements: announcements || [],
                        csrfToken: req.csrfToken ? req.csrfToken() : ''
                    });
                });
            });
        });
    });
});

app.post('/dashboard/settings', requireLogin, upload.single('profile_pic'), (req, res) => {
    try {
        const currentUsername = req.session.user.username;
        const newUsername = req.body.username ? sanitizeInput(req.body.username.trim()) : null;
        let profilePicFilename = req.file ? req.file.filename : null;
        
        if (req.file) {
            const allowedMimeTypes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
            if (!allowedMimeTypes.includes(req.file.mimetype)) {
                logSecurityEvent('INVALID_FILE_UPLOAD', { username: currentUsername, mimetype: req.file.mimetype });
                return res.status(400).json({ error: 'Invalid file type. Only images are allowed.' });
            }
            
            if (req.file.size > 5 * 1024 * 1024) {
                logSecurityEvent('FILE_TOO_LARGE', { username: currentUsername, size: req.file.size });
                return res.status(400).json({ error: 'File too large. Maximum size is 5MB.' });
            }
        }
        
        if (newUsername && newUsername !== currentUsername) {
            if (!validateUsername(newUsername)) {
                logSecurityEvent('INVALID_USERNAME_UPDATE', { username: currentUsername, newUsername });
                return res.status(400).json({ error: 'Invalid username format.' });
            }
            
            db.get('SELECT username FROM users WHERE username = ? AND username != ?', [newUsername, currentUsername], (err, existingUser) => {
                if (err) {
                    logSecurityEvent('DB_ERROR', { operation: 'username_check', error: err.message, username: currentUsername });
                    return res.status(500).json({ error: 'Database error.', details: err.message });
                }
                if (existingUser) {
                    logSecurityEvent('USERNAME_TAKEN', { username: currentUsername, attemptedUsername: newUsername });
                    return res.json({ success: false, error: 'Username already taken.' });
                }
                
                db.run('UPDATE users SET username = ? WHERE username = ?', [newUsername, currentUsername], function(err) {
                    if (err) {
                        logSecurityEvent('DB_ERROR', { operation: 'username_update', error: err.message, username: currentUsername });
                        return res.status(500).json({ error: 'Database error.', details: err.message });
                    }
                    db.run('UPDATE keys SET owner = ? WHERE owner = ?', [newUsername, currentUsername], function(err) {
                        if (err) {
                            logSecurityEvent('DB_ERROR', { operation: 'keys_update', error: err.message, username: currentUsername });
                            return res.status(500).json({ error: 'Database error updating keys.', details: err.message });
                        }
                        req.session.user.username = newUsername;
                        
                        logSecurityEvent('USERNAME_CHANGED', { oldUsername: currentUsername, newUsername });
                        
                        if (profilePicFilename) {
                            db.run('UPDATE users SET profile_pic = ? WHERE username = ?', [profilePicFilename, newUsername], function(err) {
                                if (err) {
                                    logSecurityEvent('DB_ERROR', { operation: 'profile_pic_update', error: err.message, username: newUsername });
                                    return res.status(500).json({ error: 'Database error.', details: err.message });
                                }
                                let profilePicUrl = '/uploads/' + profilePicFilename;
                                res.json({ success: true, profilePicUrl, username: newUsername });
                            });
                        } else {
                            res.json({ success: true, username: newUsername });
                        }
                    });
                });
            });
        } else {
            if (!profilePicFilename) {
                return res.json({ success: false, error: 'No changes to save.' });
            }
            
            db.run('UPDATE users SET profile_pic = ? WHERE username = ?', [profilePicFilename, currentUsername], function(err) {
                if (err) {
                    logSecurityEvent('DB_ERROR', { operation: 'profile_pic_update', error: err.message, username: currentUsername });
                    return res.status(500).json({ error: 'Database error.', details: err.message });
                }
                
                logSecurityEvent('PROFILE_PIC_UPDATED', { username: currentUsername });
                let profilePicUrl = '/uploads/' + profilePicFilename;
                res.json({ success: true, profilePicUrl });
            });
        }
    } catch (err) {
        logSecurityEvent('SETTINGS_ROUTE_ERROR', { error: err.message, stack: err.stack });
        res.status(500).json({ error: 'Internal server error.', details: err.message, stack: err.stack });
    }
});

app.get('/admin/users', requireLogin, requireAdmin, (req, res) => {
    db.all('SELECT username, plan, is_admin, banned, rate_limited FROM users', (err, rows) => {
        if (err) return res.status(500).json({ error: 'Database error.' });
        res.json({ users: rows });
    });
});
app.post('/admin/user/:username/ban', requireLogin, requireAdmin, (req, res) => {
    const { username } = req.params;
    const { ban } = req.body;
    db.run('UPDATE users SET banned = ? WHERE username = ?', [ban ? 1 : 0, username], function(err) {
        if (err) return res.status(500).json({ error: 'Database error.' });
        if (req.session.user && req.session.user.username === username && ban) {
            req.session.destroy(() => {
                res.json({ success: true, username, banned: !!ban, forceLogout: true });
            });
        } else {
            res.json({ success: true, username, banned: !!ban });
        }
    });
});
app.post('/admin/user/:username/ratelimit', requireLogin, requireAdmin, (req, res) => {
    const { username } = req.params;
    const { rate_limited } = req.body;
    db.run('UPDATE users SET rate_limited = ? WHERE username = ?', [rate_limited ? 1 : 0, username], function(err) {
        if (err) return res.status(500).json({ error: 'Database error.' });
        if (req.session.user && req.session.user.username === username) {
            req.session.user.rate_limited = !!rate_limited;
        }
        res.json({ success: true, username, rate_limited: !!rate_limited });
    });
});
app.post('/admin/user/:username/plan', requireLogin, requireAdmin, (req, res) => {
    const { username } = req.params;
    const { plan } = req.body;
    setUserPlan(db, username, plan, function(err) {
        if (err) return res.status(500).json({ error: 'Database error.' });
        if (req.session.user && req.session.user.username === username) {
            req.session.user.plan = plan;
        }
        res.json({ success: true, username, plan });
    });
});
app.post('/admin/user/:username/admin', requireLogin, requireAdmin, (req, res) => {
    const { username } = req.params;
    const { is_admin } = req.body;
    db.run('UPDATE users SET is_admin = ? WHERE username = ?', [is_admin ? 1 : 0, username], function(err) {
        if (err) return res.status(500).json({ error: 'Database error.' });
        if (req.session.user && req.session.user.username === username) {
            req.session.user.is_admin = !!is_admin;
        }
        res.json({ success: true, username, is_admin: !!is_admin });
    });
});
app.post('/admin/announcement', requireLogin, requireAdmin, (req, res) => {
    const { message, target_user } = req.body;
    if (!message || !message.trim()) return res.json({ success: false, error: 'Message required.' });
    db.run('INSERT INTO announcements (target_user, message, created_at) VALUES (?, ?, ?)', [target_user || null, message.trim(), new Date().toISOString()], function(err) {
        if (err) return res.json({ success: false, error: 'Database error.' });
        res.json({ success: true });
    });
});
app.get('/admin/announcements', requireLogin, requireAdmin, (req, res) => {
    db.all('SELECT id, target_user, message, created_at FROM announcements ORDER BY created_at DESC', (err, rows) => {
        if (err) return res.status(500).json({ error: 'Database error.' });
        res.json({ announcements: rows });
    });
});
app.delete('/admin/announcement/:id', requireLogin, requireAdmin, (req, res) => {
    const { id } = req.params;
    db.run('DELETE FROM announcements WHERE id = ?', [id], function(err) {
        if (err) return res.status(500).json({ error: 'Database error.' });
        if (this.changes === 0) return res.status(404).json({ error: 'Announcement not found.' });
        res.json({ success: true });
    });
});

app.post('/admin/fix-admin-plan', requireLogin, requireAdmin, (req, res) => {
    db.get('SELECT username, plan FROM users WHERE username = ?', ['admin'], (err, userRow) => {
        if (err) {
            console.log('Database error checking admin user:', err);
            return res.status(500).json({ error: 'Database error checking admin user.' });
        }
        
        if (!userRow) {
            console.log('Admin user not found');
            return res.status(404).json({ error: 'Admin user not found.' });
        }
        
        console.log('Admin user current plan:', userRow.plan);
        
        if (!userRow.plan) {
            db.run('UPDATE users SET plan = ? WHERE username = ?', ['lifetime', 'admin'], function(err) {
                if (err) {
                    console.log('Database error fixing admin plan:', err);
                    return res.status(500).json({ error: 'Database error fixing admin plan.' });
                }
                
                console.log('Successfully fixed admin user plan to lifetime');
                res.json({ success: true, message: 'Admin user plan fixed to lifetime', plan: 'lifetime' });
            });
        } else {
            res.json({ success: true, message: 'Admin user already has a plan', plan: userRow.plan });
        }
    });
});

app.post('/search', requireLogin, async (req, res) => {
    const username = req.session.user.username;
    const { query } = req.body;
    const sanitizedQuery = query ? sanitizeInput(query) : '';
    if (req.session.user.rate_limited) {
        const now = Date.now();
        if (!req.session.user.lastSearchTime || now - req.session.user.lastSearchTime > 60000) {
            req.session.user.lastSearchTime = now;
        } else {
            return res.render('ratelimit');
        }
    }
    if (req.session.user.banned) {
        searchStats.failed++;
        return res.status(403).json({ error: 'Account banned.' });
    }
    if (!validateQuery(sanitizedQuery)) {
        searchStats.failed++;
        return res.status(400).json({ error: 'Invalid query format.' });
    }
    const suspiciousPatterns = [
        /<script/i,
        /javascript:/i,
        /on\w+\s*=/i,
        /union\s+select/i,
        /drop\s+table/i,
        /delete\s+from/i,
        /insert\s+into/i,
        /update\s+set/i
    ];
    if (suspiciousPatterns.some(pattern => pattern.test(sanitizedQuery))) {
        searchStats.failed++;
        return res.status(400).json({ error: 'Query contains invalid characters.' });
    }
    db.run('INSERT INTO searches (user, query) VALUES (?, ?)', [username, sanitizedQuery], function(err) {
        if (err) {
            searchStats.failed++;
            logSecurityEvent('SEARCH_ERROR', { error: err.message });
            return res.status(500).json({ error: 'Database error.' });
        }
        searchStats.searches++;
        const results = [
            { title: 'Search Result 1', description: `Results for: ${sanitizedQuery}` },
            { title: 'Search Result 2', description: 'Additional search results...' },
            { title: 'Search Result 3', description: 'More results...' }
        ];
        res.json({ success: true, results, query: sanitizedQuery });
    });
});

app.get('/api/search-stats', requireLogin, (req, res) => {
    res.json({
        searches: searchStats.searches,
        failed: searchStats.failed
    });
});

app.get('/api/daily-searches', requireLogin, (req, res) => {
    const username = req.session.user.username;
    const today = new Date().toISOString().split('T')[0];
    
    db.get('SELECT COUNT(*) as count FROM searches WHERE user = ? AND DATE(timestamp) = ?', [username, today], (err, row) => {
        if (err) return res.status(500).json({ error: 'Database error.' });
        res.json({ dailySearches: row ? row.count : 0 });
    });
});

app.get('/api/check-apis', requireLogin, (req, res) => {
    const https = require('https');
    const apis = [
        { name: 'snusbase', url: 'https://api.snusbase.com' },
        { name: 'breachdirectory', url: 'https://breachdirectory.p.rapidapi.com' },
        { name: 'dehashed', url: 'https://api.dehashed.com' }
    ];
    
    const results = {};
    let completed = 0;
    
    apis.forEach(api => {
        const httpsReq = https.request(api.url, { method: 'HEAD', timeout: 5000 }, (httpsRes) => {
            results[api.name] = httpsRes.statusCode < 400 ? 'online' : 'offline';
            completed++;
            if (completed === apis.length) {
                res.json({ apis: results });
            }
        });
        
        httpsReq.on('error', () => {
            results[api.name] = 'offline';
            completed++;
            if (completed === apis.length) {
                res.json({ apis: results });
            }
        });
        
        httpsReq.on('timeout', () => {
            results[api.name] = 'offline';
            completed++;
            if (completed === apis.length) {
                res.json({ apis: results });
            }
            httpsReq.destroy();
        });
        
        httpsReq.end();
    });
});

app.get('/alerts', requireLogin, (req, res) => {
    const username = req.session.user.username;
    db.all('SELECT * FROM announcements WHERE target_user IS NULL OR target_user = ? ORDER BY created_at DESC', [username], (err, rows) => {
        if (err) return res.status(500).json({ error: 'Database error.' });
        res.json({ alerts: rows });
    });
});

// OSINT Dog API Configuration
const OSINTDOG_API_KEY = process.env.OSINTDOG_API_KEY;
const OSINTDOG_BASE_URL = 'https://osintdog.com/api';

// Rate limiters for different OSINT services
const osintLimiter = rateLimit({
    windowMs: 60 * 1000, 
    max: 5, 
    message: 'Too many OSINT requests, please slow down.',
    standardHeaders: true,
    legacyHeaders: false,
});

// Universal Search - Search across all available intelligence sources
app.post('/api/universal-search', osintLimiter, requireLogin, async (req, res) => {
    if (!req.session.user || !['monthly', 'yearly', 'lifetime'].includes(req.session.user.plan)) {
        return res.status(403).json({ error: 'Upgrade your plan to use this feature.' });
    }
    
    try {
        const allowedFields = ['email', 'username', 'phone', 'domain', 'ip'];
        const { field, value } = req.body;
        
        if (!field || !value || !allowedFields.includes(field)) {
            logSecurityEvent('UNIVERSAL_SEARCH_INVALID_INPUT', { user: req.session.user.username, field, value });
            return res.status(400).json({ error: 'Invalid search field or value.' });
        }
        
        // Validate input format
        let valid = false;
        switch (field) {
            case 'email':
                valid = validator.isEmail(value);
                break;
            case 'username':
                valid = /^[a-zA-Z0-9_\-.]{3,32}$/.test(value);
                break;
            case 'phone':
                valid = validator.isMobilePhone(value, 'any');
                break;
            case 'domain':
                valid = validator.isFQDN(value);
                break;
            case 'ip':
                valid = validator.isIP(value);
                break;
        }
        
        if (!valid) {
            logSecurityEvent('UNIVERSAL_SEARCH_INVALID_FORMAT', { user: req.session.user.username, field, value });
            return res.status(400).json({ error: 'Invalid value format.' });
        }
        
        const fetch = require('node-fetch');
        const payload = { field: [ { [field]: value } ] };
        
        const apiRes = await fetch(`${OSINTDOG_BASE_URL}/search`, {
            method: 'POST',
            headers: {
                'X-API-Key': OSINTDOG_API_KEY,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(payload),
            timeout: 15000
        });
        
        const data = await apiRes.json();
        logSecurityEvent('UNIVERSAL_SEARCH_QUERY', { user: req.session.user.username, field, value });
        
        if (!data.success) {
            return res.status(502).json({ error: 'Universal search API error.' });
        }
        
        res.json({
            success: true,
            search_term: data.search_term,
            search_type: data.search_type,
            results: data.results
        });
    } catch (err) {
        logSecurityEvent('UNIVERSAL_SEARCH_ERROR', { user: req.session?.user?.username, error: err.message });
        res.status(500).json({ error: 'Internal server error.' });
    }
});

// Snusbase Database Search
app.post('/api/snusbase/search', osintLimiter, requireLogin, async (req, res) => {
    if (!req.session.user || !['monthly', 'yearly', 'lifetime'].includes(req.session.user.plan)) {
        return res.status(403).json({ error: 'Upgrade your plan to use this feature.' });
    }
    
    try {
        const { terms, types, wildcard = false, group_by = 'db', tables = null } = req.body;
        
        if (!terms || !Array.isArray(terms) || terms.length === 0) {
            return res.status(400).json({ error: 'Terms array is required.' });
        }
        
        const fetch = require('node-fetch');
        const payload = { terms, types, wildcard, group_by, tables };
        
        const apiRes = await fetch(`${OSINTDOG_BASE_URL}/snusbase/search`, {
            method: 'POST',
            headers: {
                'X-API-Key': OSINTDOG_API_KEY,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(payload),
            timeout: 20000
        });
        
        const data = await apiRes.json();
        logSecurityEvent('SNUSBASE_SEARCH', { user: req.session.user.username, terms });
        
        res.json(data);
    } catch (err) {
        logSecurityEvent('SNUSBASE_ERROR', { user: req.session?.user?.username, error: err.message });
        res.status(500).json({ error: 'Internal server error.' });
    }
});

// LeakCheck v2 Search
app.post('/api/leakcheck/v2', osintLimiter, requireLogin, async (req, res) => {
    if (!req.session.user || !['monthly', 'yearly', 'lifetime'].includes(req.session.user.plan)) {
        return res.status(403).json({ error: 'Upgrade your plan to use this feature.' });
    }
    
    try {
        const { term, search_type, limit = 1000, offset = 0 } = req.body;
        
        if (!term || !search_type) {
            return res.status(400).json({ error: 'Term and search_type are required.' });
        }
        
        const fetch = require('node-fetch');
        const payload = { term, search_type, limit, offset };
        
        const apiRes = await fetch(`${OSINTDOG_BASE_URL}/leakcheck/v2`, {
            method: 'POST',
            headers: {
                'X-API-Key': OSINTDOG_API_KEY,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(payload),
            timeout: 15000
        });
        
        const data = await apiRes.json();
        logSecurityEvent('LEAKCHECK_SEARCH', { user: req.session.user.username, term, search_type });
        
        res.json(data);
    } catch (err) {
        logSecurityEvent('LEAKCHECK_ERROR', { user: req.session?.user?.username, error: err.message });
        res.status(500).json({ error: 'Internal server error.' });
    }
});

// HackCheck Search
app.post('/api/hackcheck', osintLimiter, requireLogin, async (req, res) => {
    if (!req.session.user || !['monthly', 'yearly', 'lifetime'].includes(req.session.user.plan)) {
        return res.status(403).json({ error: 'Upgrade your plan to use this feature.' });
    }
    
    try {
        const { term, search_type } = req.body;
        
        if (!term || !search_type) {
            return res.status(400).json({ error: 'Term and search_type are required.' });
        }
        
        const fetch = require('node-fetch');
        const payload = { term, search_type };
        
        const apiRes = await fetch(`${OSINTDOG_BASE_URL}/hackcheck`, {
            method: 'POST',
            headers: {
                'X-API-Key': OSINTDOG_API_KEY,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(payload),
            timeout: 15000
        });
        
        const data = await apiRes.json();
        logSecurityEvent('HACKCHECK_SEARCH', { user: req.session.user.username, term, search_type });
        
        res.json(data);
    } catch (err) {
        logSecurityEvent('HACKCHECK_ERROR', { user: req.session?.user?.username, error: err.message });
        res.status(500).json({ error: 'Internal server error.' });
    }
});

// BreachBase Search
app.post('/api/breachbase', osintLimiter, requireLogin, async (req, res) => {
    if (!req.session.user || !['monthly', 'yearly', 'lifetime'].includes(req.session.user.plan)) {
        return res.status(403).json({ error: 'Upgrade your plan to use this feature.' });
    }
    
    try {
        const { term, search_type } = req.body;
        
        if (!term || !search_type) {
            return res.status(400).json({ error: 'Term and search_type are required.' });
        }
        
        const fetch = require('node-fetch');
        const payload = { term, search_type };
        
        const apiRes = await fetch(`${OSINTDOG_BASE_URL}/breachbase`, {
            method: 'POST',
            headers: {
                'X-API-Key': OSINTDOG_API_KEY,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(payload),
            timeout: 15000
        });
        
        const data = await apiRes.json();
        logSecurityEvent('BREACHBASE_SEARCH', { user: req.session.user.username, term, search_type });
        
        res.json(data);
    } catch (err) {
        logSecurityEvent('BREACHBASE_ERROR', { user: req.session?.user?.username, error: err.message });
        res.status(500).json({ error: 'Internal server error.' });
    }
});

// IntelVault Search
app.post('/api/intelvault', osintLimiter, requireLogin, async (req, res) => {
    if (!req.session.user || !['monthly', 'yearly', 'lifetime'].includes(req.session.user.plan)) {
        return res.status(403).json({ error: 'Upgrade your plan to use this feature.' });
    }
    
    try {
        const { field } = req.body;
        
        if (!field || !Array.isArray(field) || field.length === 0) {
            return res.status(400).json({ error: 'Field array is required.' });
        }
        
        const fetch = require('node-fetch');
        const payload = { field };
        
        const apiRes = await fetch(`${OSINTDOG_BASE_URL}/intelvault`, {
            method: 'POST',
            headers: {
                'X-API-Key': OSINTDOG_API_KEY,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(payload),
            timeout: 15000
        });
        
        const data = await apiRes.json();
        logSecurityEvent('INTELVAULT_SEARCH', { user: req.session.user.username, field });
        
        res.json(data);
    } catch (err) {
        logSecurityEvent('INTELVAULT_ERROR', { user: req.session?.user?.username, error: err.message });
        res.status(500).json({ error: 'Internal server error.' });
    }
});

// OathNet Services
app.post('/api/oathnet/:service', osintLimiter, requireLogin, async (req, res) => {
    if (!req.session.user || !['monthly', 'yearly', 'lifetime'].includes(req.session.user.plan)) {
        return res.status(403).json({ error: 'Upgrade your plan to use this feature.' });
    }
    
    try {
        const { service } = req.params;
        const { query, ...params } = req.body;
        
        if (!query) {
            return res.status(400).json({ error: 'Query parameter is required.' });
        }
        
        const fetch = require('node-fetch');
        let url = `${OSINTDOG_BASE_URL}/oathnet/${service}`;
        
        // For GET requests, add query parameters
        if (['holehe', 'ghunt', 'roblox-userinfo', 'discord-to-roblox', 'steam-userinfo', 'xbox-userinfo', 'minecraft-history'].includes(service)) {
            const searchParams = new URLSearchParams({ q: query, ...params });
            url += `?${searchParams.toString()}`;
            
            const apiRes = await fetch(url, {
                method: 'GET',
                headers: {
                    'X-API-Key': OSINTDOG_API_KEY,
                    'Content-Type': 'application/json'
                },
                timeout: 15000
            });
            
            const data = await apiRes.json();
            logSecurityEvent('OATHNET_SEARCH', { user: req.session.user.username, service, query });
            
            res.json(data);
        } else {
            return res.status(400).json({ error: 'Invalid OathNet service.' });
        }
    } catch (err) {
        logSecurityEvent('OATHNET_ERROR', { user: req.session?.user?.username, error: err.message });
        res.status(500).json({ error: 'Internal server error.' });
    }
});

// INF0SEC Services
app.get('/api/inf0sec/:module', osintLimiter, requireLogin, async (req, res) => {
    if (!req.session.user || !['monthly', 'yearly', 'lifetime'].includes(req.session.user.plan)) {
        return res.status(403).json({ error: 'Upgrade your plan to use this feature.' });
    }
    
    try {
        const { module } = req.params;
        const { q, ...params } = req.query;
        
        if (!q) {
            return res.status(400).json({ error: 'Query parameter is required.' });
        }
        
        const fetch = require('node-fetch');
        const searchParams = new URLSearchParams({ q, ...params });
        const url = `${OSINTDOG_BASE_URL}/inf0sec/${module}?${searchParams.toString()}`;
        
        const apiRes = await fetch(url, {
            method: 'GET',
            headers: {
                'X-API-Key': OSINTDOG_API_KEY,
                'Content-Type': 'application/json'
            },
            timeout: 15000
        });
        
        const data = await apiRes.json();
        logSecurityEvent('INF0SEC_SEARCH', { user: req.session.user.username, module, query: q });
        
        res.json(data);
    } catch (err) {
        logSecurityEvent('INF0SEC_ERROR', { user: req.session?.user?.username, error: err.message });
        res.status(500).json({ error: 'Internal server error.' });
    }
});

// SEON Services
app.get('/api/seon/:service', osintLimiter, requireLogin, async (req, res) => {
    if (!req.session.user || !['monthly', 'yearly', 'lifetime'].includes(req.session.user.plan)) {
        return res.status(403).json({ error: 'Upgrade your plan to use this feature.' });
    }
    
    try {
        const { service } = req.params;
        const { email, phone } = req.query;
        
        if (!email && !phone) {
            return res.status(400).json({ error: 'Email or phone parameter is required.' });
        }
        
        const fetch = require('node-fetch');
        const searchParams = new URLSearchParams();
        if (email) searchParams.append('email', email);
        if (phone) searchParams.append('phone', phone);
        
        const url = `${OSINTDOG_BASE_URL}/seon/${service}?${searchParams.toString()}`;
        
        const apiRes = await fetch(url, {
            method: 'GET',
            headers: {
                'X-API-Key': OSINTDOG_API_KEY,
                'Content-Type': 'application/json'
            },
            timeout: 15000
        });
        
        const data = await apiRes.json();
        logSecurityEvent('SEON_SEARCH', { user: req.session.user.username, service, query: email || phone });
        
        res.json(data);
    } catch (err) {
        logSecurityEvent('SEON_ERROR', { user: req.session?.user?.username, error: err.message });
        res.status(500).json({ error: 'Internal server error.' });
    }
});

const COURTLISTENER_API_KEY = process.env.COURTLISTENER_API_KEY;
const courtListenerLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 10,
    message: 'Too many Court Search requests, please slow down.',
    standardHeaders: true,
    legacyHeaders: false,
});

app.post('/api/courtsearch', courtListenerLimiter, requireLogin, async (req, res) => {
    if (!req.session.user || !['monthly', 'yearly', 'lifetime'].includes(req.session.user.plan)) {
        return res.status(403).json({ error: 'Upgrade your plan to use this feature.' });
    }
    if (req.session.user.rate_limited) {
        const now = Date.now();
        if (!req.session.user.lastCourtSearchTime || now - req.session.user.lastCourtSearchTime > 60000) {
            req.session.user.lastCourtSearchTime = now;
        } else {
            return res.status(429).json({ error: 'You are rate limited. Please wait before searching again.' });
        }
    }
    try {
        const { type, query } = req.body;
        const allowedTypes = ['o', 'r', 'd', 'rd', 'p', 'oa'];
        if (!type || !query || typeof query !== 'string' || !allowedTypes.includes(type)) {
            return res.status(400).json({ error: 'Invalid search type or query.' });
        }
        const fetch = require('node-fetch');
        const url = `https://www.courtlistener.com/api/rest/v4/search/?q=${encodeURIComponent(query)}&type=${type}`;
        const apiRes = await fetch(url, {
            method: 'GET',
            headers: {
                'Authorization': `Token ${COURTLISTENER_API_KEY}`
            },
            timeout: 20000
        });
        const data = await apiRes.json();
        if (!apiRes.ok) {
            return res.status(502).json({ error: data.detail || 'CourtListener API error.' });
        }
        res.json({
            success: true,
            count: data.count,
            next: data.next,
            previous: data.previous,
            results: data.results
        });
    } catch (err) {
        res.status(500).json({ error: 'Internal server error.' });
    }
});

const IBAN_ABSTRACT_API_KEY = process.env.IBAN_ABSTRACT_API_KEY;
const IBAN_API_KEY = process.env.IBAN_API_KEY;
const ibanLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 3,
    message: 'Too many IBAN requests, please slow down.',
    standardHeaders: true,
    legacyHeaders: false,
});

app.post('/api/iban/validate', ibanLimiter, requireLogin, async (req, res) => {
    if (!req.session.user || !['monthly', 'yearly', 'lifetime'].includes(req.session.user.plan)) {
        return res.status(403).json({ error: 'Upgrade your plan to use this feature.' });
    }
    if (req.session.user.rate_limited) {
        const now = Date.now();
        if (!req.session.user.lastIbanTime || now - req.session.user.lastIbanTime > 60000) {
            req.session.user.lastIbanTime = now;
        } else {
            return res.status(429).json({ error: 'You are rate limited. Please wait before searching again.' });
        }
    }
    try {
        const { iban } = req.body;
        if (!iban || typeof iban !== 'string' || iban.length < 8 || iban.length > 34) {
            logSecurityEvent('IBAN_INVALID_INPUT', { user: req.session.user.username, iban });
            return res.status(400).json({ error: 'Invalid IBAN.' });
        }
        const fetch = require('node-fetch');
        const url = `https://ibanvalidation.abstractapi.com/v1/?api_key=${IBAN_ABSTRACT_API_KEY}&iban=${encodeURIComponent(iban)}`;
        const apiRes = await fetch(url, { timeout: 10000 });
        const data = await apiRes.json();
        logSecurityEvent('IBAN_QUERY', { user: req.session.user.username });
        if (!data || typeof data !== 'object' || !('iban' in data)) {
            return res.status(502).json({ error: 'IBAN API error.' });
        }
        res.json({
            success: true,
            search_term: data.iban,
            search_type: 'iban',
            results: data
        });
    } catch (err) {
        logSecurityEvent('IBAN_ERROR', { user: req.session?.user?.username, error: err.message });
        res.status(500).json({ error: 'Internal server error.' });
    }
});

const ABSTRACT_EMAIL_VALIDATION_API_KEY = process.env.ABSTRACT_EMAIL_VALIDATION_API_KEY;
const ABSTRACT_EMAIL_REPUTATION_API_KEY = process.env.ABSTRACT_EMAIL_REPUTATION_API_KEY;
const ABSTRACT_PHONE_VALIDATION_API_KEY = process.env.ABSTRACT_PHONE_VALIDATION_API_KEY;
const ABSTRACT_VAT_VALIDATION_API_KEY = process.env.ABSTRACT_VAT_VALIDATION_API_KEY;

const abstractLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 5,
    message: 'Too many Abstract API requests, please slow down.',
    standardHeaders: true,
    legacyHeaders: false,
});

app.post('/api/abstract/email/validate', abstractLimiter, requireLogin, async (req, res) => {
    if (!req.session.user || !['monthly', 'yearly', 'lifetime'].includes(req.session.user.plan)) {
        return res.status(403).json({ error: 'Upgrade your plan to use this feature.' });
    }
    try {
        const { email } = req.body;
        if (!email || typeof email !== 'string' || !validator.isEmail(email)) {
            return res.status(400).json({ error: 'Invalid email.' });
        }
        const fetch = require('node-fetch');
        const url = `https://emailvalidation.abstractapi.com/v1/?api_key=${ABSTRACT_EMAIL_VALIDATION_API_KEY}&email=${encodeURIComponent(email)}`;
        const apiRes = await fetch(url, { timeout: 10000 });
        const data = await apiRes.json();
        if (!data || typeof data !== 'object') {
            return res.status(502).json({ error: 'Abstract Email Validation API error.' });
        }
        if (data.error || !('email' in data)) {
            return res.json({ success: false, results: data, error: data.error && data.error.message ? data.error.message : 'Abstract API error.' });
        }
        res.json({ success: true, results: data });
    } catch (err) {
        res.status(500).json({ error: 'Internal server error.' });
    }
});

app.post('/api/abstract/email/reputation', abstractLimiter, requireLogin, async (req, res) => {
    if (!req.session.user || !['monthly', 'yearly', 'lifetime'].includes(req.session.user.plan)) {
        return res.status(403).json({ error: 'Upgrade your plan to use this feature.' });
    }
    try {
        const { email } = req.body;
        if (!email || typeof email !== 'string' || !validator.isEmail(email)) {
            return res.status(400).json({ error: 'Invalid email.' });
        }
        const fetch = require('node-fetch');
        const url = `https://emailreputation.abstractapi.com/v1/?api_key=${ABSTRACT_EMAIL_REPUTATION_API_KEY}&email=${encodeURIComponent(email)}`;
        const apiRes = await fetch(url, { timeout: 10000 });
        const data = await apiRes.json();
        if (!data || typeof data !== 'object') {
            return res.status(502).json({ error: 'Abstract Email Reputation API error.' });
        }
        if (data.error || (!('email' in data) && !('email_address' in data))) {
            return res.json({ success: false, results: data, error: data.error && data.error.message ? data.error.message : 'Abstract API error.' });
        }
        res.json({ success: true, results: data });
    } catch (err) {
        res.status(500).json({ error: 'Internal server error.' });
    }
});

app.post('/api/abstract/phone/validate', abstractLimiter, requireLogin, async (req, res) => {
    if (!req.session.user || !['monthly', 'yearly', 'lifetime'].includes(req.session.user.plan)) {
        return res.status(403).json({ error: 'Upgrade your plan to use this feature.' });
    }
    try {
        const { phone } = req.body;
        if (!phone || typeof phone !== 'string' || phone.length < 5) {
            return res.status(400).json({ error: 'Invalid phone number.' });
        }
        const fetch = require('node-fetch');
        const url = `https://phonevalidation.abstractapi.com/v1/?api_key=${ABSTRACT_PHONE_VALIDATION_API_KEY}&phone=${encodeURIComponent(phone)}`;
        const apiRes = await fetch(url, { timeout: 10000 });
        const data = await apiRes.json();
        if (!data || typeof data !== 'object') {
            return res.status(502).json({ error: 'Abstract Phone Validation API error.' });
        }
        if (data.error || !('phone' in data)) {
            return res.json({ success: false, results: data, error: data.error && data.error.message ? data.error.message : 'Abstract API error.' });
        }
        res.json({ success: true, results: data });
    } catch (err) {
        res.status(500).json({ error: 'Internal server error.' });
    }
});

app.post('/api/abstract/vat/validate', abstractLimiter, requireLogin, async (req, res) => {
    if (!req.session.user || !['monthly', 'yearly', 'lifetime'].includes(req.session.user.plan)) {
        return res.status(403).json({ error: 'Upgrade your plan to use this feature.' });
    }
    try {
        const { vat } = req.body;
        if (!vat || typeof vat !== 'string' || vat.length < 5) {
            return res.status(400).json({ error: 'Invalid VAT number.' });
        }
        const fetch = require('node-fetch');
        const url = `https://vat.abstractapi.com/v1/validate/?api_key=${ABSTRACT_VAT_VALIDATION_API_KEY}&vat_number=${encodeURIComponent(vat)}`;
        const apiRes = await fetch(url, { timeout: 10000 });
        const data = await apiRes.json();
        if (!data || typeof data !== 'object') {
            return res.status(502).json({ error: 'Abstract VAT Validation API error.' });
        }
        if (data.error || (!('vat' in data) && !('vat_number' in data))) {
            return res.json({ success: false, results: data, error: data.error && data.error.message ? data.error.message : 'Abstract API error.' });
        }
        res.json({ success: true, results: data });
    } catch (err) {
        res.status(500).json({ error: 'Internal server error.' });
    }
});

app.post('/api/abstract/iban/validate', abstractLimiter, requireLogin, async (req, res) => {
    if (!req.session.user || !['monthly', 'yearly', 'lifetime'].includes(req.session.user.plan)) {
        return res.status(403).json({ error: 'Upgrade your plan to use this feature.' });
    }
    try {
        const { iban } = req.body;
        if (!iban || typeof iban !== 'string' || iban.length < 8 || iban.length > 34) {
            return res.status(400).json({ error: 'Invalid IBAN.' });
        }
        const fetch = require('node-fetch');
        const url = `https://ibanvalidation.abstractapi.com/v1/?api_key=${IBAN_ABSTRACT_API_KEY}&iban=${encodeURIComponent(iban)}`;
        const apiRes = await fetch(url, { timeout: 10000 });
        const data = await apiRes.json();
        if (!data || typeof data !== 'object') {
            return res.status(502).json({ error: 'Abstract IBAN Validation API error.' });
        }
        if (data.error || !('iban' in data)) {
            return res.json({ success: false, results: data, error: data.error && data.error.message ? data.error.message : 'Abstract API error.' });
        }
        res.json({ success: true, results: data });
    } catch (err) {
        res.status(500).json({ error: 'Internal server error.' });
    }
});

app.get('/api/ipinfo', requireLogin, async (req, res) => {
    const ip = req.query.ip;
    if (!ip || typeof ip !== 'string' || !/^([0-9]{1,3}\.){3}[0-9]{1,3}$/.test(ip)) {
        return res.status(400).json({ error: 'Invalid IP address.' });
    }
    try {
        const token = '0f14eb84b0a211';
        const url = `https://ipinfo.io/${ip}?token=${token}`;
        const response = await axios.get(url, { timeout: 5000 });
        res.json(response.data);
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch IP info.' });
    }
});

app.get('/api/csint/status', csintLimiter, requireLogin, async (req, res) => {
    try {
        const response = await fetch(`${CSINT_BASE_URL}/api/v2/search`, {
            method: 'GET',
            headers: {
                'Authorization': CSINT_API_KEY
            }
        });

        const data = await response.json();
        res.json(data);
    } catch (err) {
    console.error('CSINT API Error:', err);
    logSecurityEvent('CSINT_ERROR', { user: req.session?.user?.username, error: err.message, stack: err.stack });
    if (err.response) {
        console.error('Error response:', err.response.data);
        res.status(err.response.status).json({ error: err.response.data.message || 'CSINT API error' });
    } else if (err.request) {
        res.status(504).json({ error: 'CSINT API timeout' });
    } else {
        res.status(500).json({ error: 'Internal server error' });
    }
}
    
});

const WHATSAPP_OSINT_API_KEY = process.env.WHATSAPP_OSINT_API_KEY;
const whatsappOsintLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 5,
    message: 'Too many WhatsApp OSINT requests, please slow down.',
    standardHeaders: true,
    legacyHeaders: false,
});

app.post('/api/whatsapposint', whatsappOsintLimiter, requireLogin, async (req, res) => {
    if (!req.session.user || !['monthly', 'yearly', 'lifetime'].includes(req.session.user.plan)) {
        return res.status(403).json({ error: 'Upgrade your plan to use this feature.' });
    }
    if (req.session.user.rate_limited) {
        const now = Date.now();
        if (!req.session.user.lastWhatsappOsintTime || now - req.session.user.lastWhatsappOsintTime > 60000) {
            req.session.user.lastWhatsappOsintTime = now;
        } else {
            return res.status(429).json({ error: 'You are rate limited. Please wait before searching again.' });
        }
    }
    try {
        const { phone } = req.body;
        if (!phone || typeof phone !== 'string' || !/^\d{8,20}$/.test(phone)) {
            return res.status(400).json({ error: 'Invalid phone number.' });
        }
        const fetch = require('node-fetch');
        const url = `https://whatsapp-osint.p.rapidapi.com/wspic/b64?phone=${encodeURIComponent(phone)}`;
        const apiRes = await fetch(url, {
            method: 'GET',
            headers: {
                'x-rapidapi-key': WHATSAPP_OSINT_API_KEY,
                'x-rapidapi-host': 'whatsapp-osint.p.rapidapi.com'
            },
            timeout: 20000
        });
        let data, rawText;
        try {
            rawText = await apiRes.text();
            data = JSON.parse(rawText);
        } catch (e) {
            data = { raw: rawText };
        }
        if (!apiRes.ok) {
            console.error('WhatsApp OSINT API error:', data);
            return res.status(502).json({ error: data.detail || data.message || JSON.stringify(data) || 'WhatsApp OSINT API error.' });
        }
        res.json({
            success: true,
            ...data
        });
    } catch (err) {
        console.error('WhatsApp OSINT route error:', err && err.stack ? err.stack : err);
        res.status(500).json({ error: 'Internal server error.' });
    }
});

const TWITTER_COMMUNITY_API_KEY = process.env.TWITTER_COMMUNITY_API_KEY;
const twitterCommunityLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 5,
    message: 'Too many Twitter Community requests, please slow down.',
    standardHeaders: true,
    legacyHeaders: false,
});

app.post('/api/twittercommunity', twitterCommunityLimiter, requireLogin, async (req, res) => {
    if (!req.session.user || !['monthly', 'yearly', 'lifetime'].includes(req.session.user.plan)) {
        return res.status(403).json({ error: 'Upgrade your plan to use this feature.' });
    }
    if (req.session.user.rate_limited) {
        const now = Date.now();
        if (!req.session.user.lastTwitterCommunityTime || now - req.session.user.lastTwitterCommunityTime > 60000) {
            req.session.user.lastTwitterCommunityTime = now;
        } else {
            return res.status(429).json({ error: 'You are rate limited. Please wait before searching again.' });
        }
    }
    try {
        const { communityId } = req.body;
        if (!communityId || typeof communityId !== 'string' || !/^\d{10,30}$/.test(communityId)) {
            return res.status(400).json({ error: 'Invalid Community ID.' });
        }
        const fetch = require('node-fetch');
        const url = `https://twitter241.p.rapidapi.com/community-details?communityId=${encodeURIComponent(communityId)}`;
        const apiRes = await fetch(url, {
            method: 'GET',
            headers: {
                'x-rapidapi-key': TWITTER_COMMUNITY_API_KEY,
                'x-rapidapi-host': 'twitter241.p.rapidapi.com'
            },
            timeout: 20000
        });
        let data, rawText;
        try {
            rawText = await apiRes.text();
            data = JSON.parse(rawText);
        } catch (e) {
            data = { raw: rawText };
        }
        if (!apiRes.ok) {
            console.error('Twitter Community API error:', data);
            return res.status(502).json({ error: data.detail || data.message || JSON.stringify(data) || 'Twitter Community API error.' });
        }
        res.json({
            success: true,
            ...data
        });
    } catch (err) {
        console.error('Twitter Community route error:', err && err.stack ? err.stack : err);
        res.status(500).json({ error: 'Internal server error.' });
    }
});

const TWITTER_REPLIES_API_KEY = process.env.TWITTER_REPLIES_API_KEY;
const twitterRepliesLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 5,
    message: 'Too many Twitter Replies requests, please slow down.',
    standardHeaders: true,
    legacyHeaders: false,
});

app.post('/api/twitterreplies', twitterRepliesLimiter, requireLogin, async (req, res) => {
    if (!req.session.user || !['monthly', 'yearly', 'lifetime'].includes(req.session.user.plan)) {
        return res.status(403).json({ error: 'Upgrade your plan to use this feature.' });
    }
    if (req.session.user.rate_limited) {
        const now = Date.now();
        if (!req.session.user.lastTwitterRepliesTime || now - req.session.user.lastTwitterRepliesTime > 60000) {
            req.session.user.lastTwitterRepliesTime = now;
        } else {
            return res.status(429).json({ error: 'You are rate limited. Please wait before searching again.' });
        }
    }
    try {
        const { tweetId, token } = req.body;
        if (!tweetId || typeof tweetId !== 'string' || !/^\d{10,30}$/.test(tweetId)) {
            return res.status(400).json({ error: 'Invalid Tweet ID.' });
        }
        const fetch = require('node-fetch');
        let url = `https://twitter154.p.rapidapi.com/tweet/replies/continuation?tweet_id=${encodeURIComponent(tweetId)}`;
        if (token) {
            url += `&continuation_token=${encodeURIComponent(token)}`;
        }
        const apiRes = await fetch(url, {
            method: 'GET',
            headers: {
                'x-rapidapi-key': TWITTER_REPLIES_API_KEY,
                'x-rapidapi-host': 'twitter154.p.rapidapi.com'
            },
            timeout: 20000
        });
        let data, rawText;
        try {
            rawText = await apiRes.text();
            data = JSON.parse(rawText);
        } catch (e) {
            data = { raw: rawText };
        }
        if (!apiRes.ok) {
            console.error('Twitter Replies API error:', data);
            return res.status(502).json({ error: data.detail || data.message || JSON.stringify(data) || 'Twitter Replies API error.' });
        }
        res.json({
            success: true,
            ...data
        });
    } catch (err) {
        console.error('Twitter Replies route error:', err && err.stack ? err.stack : err);
        res.status(500).json({ error: 'Internal server error.' });
    }
});

app.post('/api/csint/search', csintLimiter, requireLogin, async (req, res) => {
    if (!req.session.user || !['monthly', 'yearly', 'lifetime'].includes(req.session.user.plan)) {
        return res.status(403).json({ error: 'Upgrade your plan to use this feature.' });
    }
    
    if (req.session.user.rate_limited) {
        const now = Date.now();
        if (!req.session.user.lastCsintTime || now - req.session.user.lastCsintTime > 60000) {
            req.session.user.lastCsintTime = now;
        } else {
            return res.status(429).json({ error: 'You are rate limited. Please wait before searching again.' });
        }
    }
    
    const { service, params } = req.body;
    
    // Validate input
    if (!service || typeof service !== 'string' || service.trim() === '') {
        return res.status(400).json({ 
            success: false,
            error: 'Service parameter is required and must be a non-empty string.',
            version: 'v2',
            timestamp: new Date().toISOString()
        });
    }
    
    if (!params || typeof params !== 'object' || Array.isArray(params)) {
        return res.status(400).json({ 
            success: false,
            error: 'Params parameter is required and must be an object.',
            version: 'v2',
            timestamp: new Date().toISOString()
        });
    }

    // List of valid services from the API documentation
    const validServices = [
        'email_intel', 'phone_intel', 'user_intel', 'seon', 'tlo', 'Intellius', 
        'court', 'caller', 'telegram', 'intelx', 'discord', 'epicgames', 
        'github', 'blockchain', 'ip', 'roblox', 'microsoft', 'stealer', 
        'dblookup', 'live_email', 'live_phone', 'breach', 'community', 
        'twitter', 'minecraft', 'portal'
    ];
    
    if (!validServices.includes(service)) {
        return res.status(400).json({ 
            success: false,
            error: `Invalid service. Valid services are: ${validServices.join(', ')}`,
            version: 'v2',
            timestamp: new Date().toISOString()
        });
    }

    try {
        console.log('CSINT API Request:', { service, params });
        
        const apiRes = await fetch(`${CSINT_BASE_URL}/api/v2/search`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': CSINT_API_KEY
            },
            body: JSON.stringify({ service, params }),
            timeout: 30000 // 30 second timeout
        });

        console.log('CSINT API Response Status:', apiRes.status);
        console.log('CSINT API Response Headers:', Object.fromEntries(apiRes.headers.entries()));

        const contentType = apiRes.headers.get('content-type');
        
        if (contentType && contentType.includes('application/json')) {
            const data = await apiRes.json();
            console.log('CSINT API JSON Response:', data);
            
            if (!apiRes.ok) {
                return res.status(apiRes.status).json({
                    success: false,
                    error: data.error || data.message || `HTTP error! status: ${apiRes.status}`,
                    details: data,
                    version: 'v2',
                    timestamp: new Date().toISOString()
                });
            }
            
            // Log successful search
            logSecurityEvent('CSINT_SEARCH', { 
                user: req.session.user.username, 
                service,
                success: true
            });
            
            res.json({
                success: true,
                ...data,
                version: 'v2',
                timestamp: new Date().toISOString()
            });
        } else {
            // Handle non-JSON responses (like streaming or text responses)
            const text = await apiRes.text();
            console.log('CSINT API Text Response:', text);
            
            if (!apiRes.ok) {
                return res.status(apiRes.status).json({
                    success: false,
                    error: text || `HTTP error! status: ${apiRes.status}`,
                    version: 'v2',
                    timestamp: new Date().toISOString()
                });
            }
            
            // For streaming responses, try to parse as JSON lines
            try {
                const lines = text.split('\n').filter(line => line.trim());
                const results = lines.map(line => JSON.parse(line));
                
                res.json({
                    success: true,
                    data: results,
                    version: 'v2',
                    timestamp: new Date().toISOString()
                });
            } catch (parseErr) {
                // If not JSON lines, return as text
                res.json({
                    success: true,
                    data: text,
                    version: 'v2',
                    timestamp: new Date().toISOString()
                });
            }
        }
    } catch (err) {
        console.error('CSINT API Error:', err);
        logSecurityEvent('CSINT_ERROR', { 
            user: req.session?.user?.username, 
            error: err.message, 
            service,
            params
        });
        
        if (err.name === 'AbortError' || err.message.includes('timeout')) {
            res.status(504).json({
                success: false,
                error: 'CSINT API timeout - request took too long',
                version: 'v2',
                timestamp: new Date().toISOString()
            });
        } else {
            res.status(500).json({
                success: false,
                error: 'CSINT API error',
                details: err.message,
                version: 'v2',
                timestamp: new Date().toISOString()
            });
        }
    }
});



app.use((err, req, res, next) => {
    const commonErrors = [
        'Failed to lookup view',
        'ENOENT',
        'favicon.ico'
    ];
    
    const shouldLog = !commonErrors.some(errorType => 
        err.message && err.message.includes(errorType)
    );
    
    if (shouldLog) {
        logSecurityEvent('ERROR', { 
            error: err.message, 
            stack: err.stack, 
            path: req.path, 
            method: req.method,
            ip: req.ip 
        });
    }
    
    if (err.code === 'LIMIT_FILE_SIZE') {
        return res.status(400).json({ error: 'File too large.' });
    }
    
    if (err.code === 'LIMIT_UNEXPECTED_FILE') {
        return res.status(400).json({ error: 'Unexpected file field.' });
    }
    
    if (err.message && err.message.includes('Failed to lookup view')) {
        return res.status(404).json({ error: 'Page not found.' });
    }
    
    res.status(500).json({ error: 'Internal server error.' });
});

app.use((req, res) => {
    logSecurityEvent('404_NOT_FOUND', { path: req.path, method: req.method, ip: req.ip });
    res.status(404).json({ error: 'Not found.' });
});

let isShuttingDown = false;

function gracefulShutdown(signal) {
    if (isShuttingDown) return;
    isShuttingDown = true;
    
    console.log(`${signal} received, shutting down gracefully...`);
    
    wss.clients.forEach(client => {
        client.close();
    });
    
    db.close((err) => {
        if (err) {
            console.error('Error closing database:', err);
        } else {
            console.log('Database connection closed');
        }
        
        server.close((err) => {
            if (err) {
                console.error('Error closing server:', err);
                process.exit(1);
            }
            console.log('HTTP server closed');
            console.log('Process terminated gracefully');
            process.exit(0);
        });
        
        setTimeout(() => {
            console.error('Forced shutdown after timeout');
            process.exit(1);
        }, 10000);
    });
}

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

process.on('uncaughtException', (err) => {
    logSecurityEvent('UNCAUGHT_EXCEPTION', { error: err.message, stack: err.stack });
    console.error('Uncaught Exception:', err);
    process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
    logSecurityEvent('UNHANDLED_REJECTION', { reason: reason.toString() });
    console.error('Unhandled Rejection at:', promise, 'reason:', reason);
    process.exit(1);
});

server.listen(PORT, () => {
    console.log(`Intelsec server running on http://localhost:${PORT}`);
    console.log('Security features enabled:');
    console.log('- Helmet (Security headers)');
    console.log('- Rate limiting');
    console.log('- XSS protection');
    console.log('- SQL injection protection');
    console.log('- Input validation');
    console.log('- File upload security');
    console.log('- CSRF protection');
    console.log('- Audit logging');
}); 
