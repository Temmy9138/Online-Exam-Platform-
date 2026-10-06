const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const { promisify } = require('node:util');
const { randomBytes, randomInt, scrypt, timingSafeEqual } = require('node:crypto');
const { DatabaseSync } = require('node:sqlite');

const scryptAsync = promisify(scrypt);
const PORT = Number(process.env.PORT) || 3002;
const ROOT = __dirname;
const DATA_DIR = path.join(ROOT, 'data');
const DB_PATH = process.env.DB_PATH ? path.resolve(process.env.DB_PATH) : path.join(DATA_DIR, 'exampro.sqlite');
const MAX_BODY_SIZE = 16 * 1024;
const sessions = new Map();
const resetRequests = new Map(); // email -> { code, expiresAt }
const resetTokens = new Map(); // token -> { email, expiresAt }
const allowedPages = new Set([
    'adminsignup.html',
    'adminlogin.html',
    'adminforgotten_password.html',
    'adminreset_verify.html',
    'adminreset_newpassword.html',
    'admin_dashbroad.html',
    'forgotten_password.html',
    'home.html',
    'login.html',
    'signup.html',
    'student_dashboard.html'
]);

fs.mkdirSync(DATA_DIR, { recursive: true });
const db = new DatabaseSync(DB_PATH);
db.exec('PRAGMA foreign_keys = ON');
db.exec(`
    CREATE TABLE IF NOT EXISTS admins (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        full_name TEXT NOT NULL,
        email TEXT NOT NULL COLLATE NOCASE UNIQUE,
        username TEXT NOT NULL COLLATE NOCASE UNIQUE,
        password_hash TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
    ;
    CREATE TABLE IF NOT EXISTS students (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        full_name TEXT NOT NULL,
        email TEXT NOT NULL COLLATE NOCASE UNIQUE,
        username TEXT NOT NULL COLLATE NOCASE UNIQUE,
        password_hash TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'blocked')),
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS subjects (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL COLLATE NOCASE UNIQUE,
        code TEXT NOT NULL COLLATE NOCASE UNIQUE,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS questions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        subject_id INTEGER NOT NULL REFERENCES subjects(id) ON DELETE CASCADE,
        prompt TEXT NOT NULL,
        choices TEXT NOT NULL,
        correct_answer INTEGER NOT NULL,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS results (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        student_id INTEGER NOT NULL REFERENCES students(id) ON DELETE CASCADE,
        subject_id INTEGER REFERENCES subjects(id) ON DELETE SET NULL,
        score REAL NOT NULL,
        total REAL NOT NULL,
        submitted_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS announcements (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        message TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
`);

function sendJson(response, statusCode, payload) {
    response.writeHead(statusCode, {
        'Content-Type': 'application/json; charset=utf-8',
        'Cache-Control': 'no-store',
        'X-Content-Type-Options': 'nosniff'
    });
    response.end(JSON.stringify(payload));
}

function createStudentAnnouncement(title, message) {
    db.prepare('INSERT INTO announcements (title, message) VALUES (?, ?)').run(title, message);
}

/* =========================
   PASSWORD RESET (demo email)
========================= */

function sendResetCodeToEmail(email, code) {
    // Local development fallback. Configure an email provider for real delivery.
    console.log(`Password reset code for ${email}: ${code}`);
}

function generateNumericCode(digits = 6) {
    return randomInt(0, 10 ** digits).toString().padStart(digits, '0');
}

async function handlePasswordResetRequest(request, response) {
    let input;
    try {
        input = await readJsonBody(request);
    } catch (err) {
        return sendJson(response, 400, { error: err.message });
    }
    if (!input || typeof input !== 'object' || Array.isArray(input)) {
        return sendJson(response, 400, { error: 'Please provide a valid email address.' });
    }
    const email = typeof input.email === 'string' ? input.email.trim().toLowerCase() : '';
    if (!email) return sendJson(response, 400, { error: 'Please provide an email address.' });
    const admin = db.prepare('SELECT id, email FROM admins WHERE email = ? COLLATE NOCASE').get(email);
    if (!admin) return sendJson(response, 404, { error: 'That email address is not registered.' });

    const code = generateNumericCode(6);
    const expiresAt = Date.now() + 15 * 60 * 1000; // 15 minutes
    resetRequests.set(admin.email.toLowerCase(), { code, expiresAt });
    sendResetCodeToEmail(admin.email, code);
    return sendJson(response, 200, {
        message: 'Reset code generated. Email delivery is not configured; check the server terminal for the code.'
    });
}

async function handlePasswordResetVerify(request, response) {
    let input;
    try {
        input = await readJsonBody(request);
    } catch (err) {
        return sendJson(response, 400, { error: err.message });
    }
    if (!input || typeof input !== 'object' || Array.isArray(input)) {
        return sendJson(response, 400, { error: 'Email and code are required.' });
    }
    const email = typeof input.email === 'string' ? input.email.trim().toLowerCase() : '';
    const code = typeof input.code === 'string' ? input.code.trim() : '';
    if (!email || !code) return sendJson(response, 400, { error: 'Email and code are required.' });
    const entry = resetRequests.get(email);
    if (!entry || entry.expiresAt < Date.now() || entry.code !== code) {
        return sendJson(response, 400, { error: 'Invalid or expired verification code.' });
    }
    // generate one-time reset token
    const token = randomBytes(24).toString('hex');
    const expiresAt = Date.now() + 15 * 60 * 1000;
    resetTokens.set(token, { email, expiresAt });
    // remove the code entry so it can't be reused
    resetRequests.delete(email);
    return sendJson(response, 200, { message: 'Code verified.', resetToken: token });
}

async function handlePasswordResetComplete(request, response) {
    let input;
    try {
        input = await readJsonBody(request);
    } catch (err) {
        return sendJson(response, 400, { error: err.message });
    }
    if (!input || typeof input !== 'object' || Array.isArray(input)) {
        return sendJson(response, 400, { error: 'Invalid reset request.' });
    }
    const token = typeof input.resetToken === 'string' ? input.resetToken.trim() : '';
    const newPassword = typeof input.newPassword === 'string' ? input.newPassword : '';
    if (!token || !newPassword) return sendJson(response, 400, { error: 'Invalid request.' });
    const info = resetTokens.get(token);
    if (!info || info.expiresAt < Date.now()) return sendJson(response, 400, { error: 'Invalid or expired reset token.' });
    const email = info.email;
    if (newPassword.length < 6 || Buffer.byteLength(newPassword, 'utf8') > 1024) return sendJson(response, 400, { error: 'Password must be 6–1024 bytes.' });
    try {
        const passwordHash = await hashPassword(newPassword);
        const result = db.prepare('UPDATE admins SET password_hash = ? WHERE email = ? COLLATE NOCASE').run(passwordHash, email);
        resetTokens.delete(token);
        return sendJson(response, 200, { message: 'Password updated successfully.' });
    } catch (err) {
        console.error('Password reset complete error:', err);
        return sendJson(response, 500, { error: 'Could not update the password.' });
    }
}

function readJsonBody(request) {
    return new Promise((resolve, reject) => {
        let body = '';
        request.setEncoding('utf8');
        request.on('data', chunk => {
            body += chunk;
            if (Buffer.byteLength(body) > MAX_BODY_SIZE) {
                reject(new Error('Request is too large.'));
                request.destroy();
            }
        });
        request.on('end', () => {
            try {
                resolve(JSON.parse(body));
            } catch {
                reject(new Error('Please send valid JSON.'));
            }
        });
        request.on('error', reject);
    });
}

async function createAdmin(request, response) {
    let input;
    try {
        input = await readJsonBody(request);
    } catch (error) {
        if (!response.destroyed) {
            sendJson(response, 400, { error: error.message });
        }
        return;
    }

    if (!input || typeof input !== 'object' || Array.isArray(input)) {
        sendJson(response, 400, { error: 'Please send valid signup details.' });
        return;
    }

    const fullName = typeof input.fullName === 'string' ? input.fullName.trim() : '';
    const email = typeof input.email === 'string' ? input.email.trim().toLowerCase() : '';
    const username = typeof input.username === 'string' ? input.username.trim() : '';
    const password = typeof input.password === 'string' ? input.password : '';

    if (input.termsAccepted !== true) {
        sendJson(response, 400, { error: 'Please accept the Terms and Conditions.' });
        return;
    }
    if (!fullName || !email || !username || !password) {
        sendJson(response, 400, { error: 'Please fill in all fields.' });
        return;
    }
    if (fullName.length > 100 || username.length > 40 || email.length > 254) {
        sendJson(response, 400, { error: 'One or more fields are too long.' });
        return;
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        sendJson(response, 400, { error: 'Please enter a valid email address.' });
        return;
    }
    if (!/^[a-zA-Z0-9_.-]{3,40}$/.test(username)) {
        sendJson(response, 400, { error: 'Username must be 3–40 characters and use letters, numbers, dots, underscores, or hyphens.' });
        return;
    }
    if (password.length < 6) {
        sendJson(response, 400, { error: 'Password must be at least 6 characters.' });
        return;
    }
    if (Buffer.byteLength(password, 'utf8') > 1024) {
        sendJson(response, 400, { error: 'Password is too long.' });
        return;
    }

    try {
        const salt = randomBytes(16).toString('hex');
        const derivedKey = await scryptAsync(password, salt, 64);
        const passwordHash = `${salt}:${derivedKey.toString('hex')}`;
        const insertAdmin = db.prepare(`
            INSERT INTO admins (full_name, email, username, password_hash)
            VALUES (?, ?, ?, ?)
        `);
        insertAdmin.run(fullName, email, username, passwordHash);
        sendJson(response, 201, { message: 'Admin account created successfully.' });
    } catch (error) {
        if (error.code === 'ERR_SQLITE_CONSTRAINT_UNIQUE' || /UNIQUE constraint failed/i.test(error.message)) {
            sendJson(response, 409, { error: 'That email address or username is already registered.' });
            return;
        }
        console.error('Signup error:', error);
        sendJson(response, 500, { error: 'Could not create the account. Please try again.' });
    }
}

function readCookie(request, name) {
    const cookies = request.headers.cookie || '';
    const entry = cookies.split(';').map(cookie => cookie.trim())
        .find(cookie => cookie.startsWith(`${name}=`));
    return entry ? entry.slice(name.length + 1) : '';
}

function getSession(request, role) {
    const token = readCookie(request, `exampro_${role}_session`);
    const session = sessions.get(token);
    if (!session || session.role !== role || session.expiresAt < Date.now()) {
        if (token) sessions.delete(token);
        return null;
    }
    return session;
}

function requireRole(request, response, role) {
    const session = getSession(request, role);
    if (!session) {
        sendJson(response, 401, { error: `Please log in as a ${role}.` });
        return null;
    }
    return session;
}

async function hashPassword(password) {
    const salt = randomBytes(16).toString('hex');
    const derivedKey = await scryptAsync(password, salt, 64);
    return `${salt}:${derivedKey.toString('hex')}`;
}

async function verifyPassword(password, passwordHash) {
    const [salt, savedHash] = passwordHash.split(':');
    if (!salt || !savedHash || !/^[a-f0-9]+$/i.test(savedHash)) return false;
    const savedKey = Buffer.from(savedHash, 'hex');
    const submittedKey = await scryptAsync(password, salt, savedKey.length);
    return savedKey.length === submittedKey.length && timingSafeEqual(savedKey, submittedKey);
}

function setSessionCookie(response, role, token, maxAge) {
    response.setHeader('Set-Cookie', `exampro_${role}_session=${token}; HttpOnly; SameSite=Strict; Path=/${maxAge ? `; Max-Age=${maxAge}` : ''}`);
}

async function loginAdmin(request, response) {
    let input;
    try {
        input = await readJsonBody(request);
    } catch (error) {
        if (!response.destroyed) {
            sendJson(response, 400, { error: error.message });
        }
        return;
    }

    if (!input || typeof input !== 'object' || Array.isArray(input)) {
        sendJson(response, 400, { error: 'Please send valid login details.' });
        return;
    }

    const identifier = typeof input.username === 'string' ? input.username.trim() : '';
    const password = typeof input.password === 'string' ? input.password : '';
    if (!identifier || !password || identifier.length > 254 || Buffer.byteLength(password, 'utf8') > 1024) {
        sendJson(response, 400, { error: 'Enter a valid username/email and password.' });
        return;
    }

    try {
        const admin = db.prepare(`
            SELECT id, username, password_hash
            FROM admins
            WHERE username = ? COLLATE NOCASE OR email = ? COLLATE NOCASE
        `).get(identifier, identifier);

        const passwordMatches = admin ? await verifyPassword(password, admin.password_hash) : false;

        if (!passwordMatches) {
            sendJson(response, 401, { error: 'Incorrect username/email or password.' });
            return;
        }

        const sessionToken = randomBytes(32).toString('hex');
        const maxAge = input.remember === true ? 60 * 60 * 24 * 30 : undefined;
        sessions.set(sessionToken, {
            role: 'admin',
            adminId: admin.id,
            expiresAt: Date.now() + (maxAge || 60 * 60 * 8) * 1000
        });
        setSessionCookie(response, 'admin', sessionToken, maxAge);
        sendJson(response, 200, {
            message: 'Login successful.',
            username: admin.username
        });
    } catch (error) {
        console.error('Login error:', error);
        sendJson(response, 500, { error: 'Could not log in. Please try again.' });
    }
}

async function createStudent(request, response) {
    let input;
    try {
        input = await readJsonBody(request);
    } catch (error) {
        sendJson(response, 400, { error: error.message });
        return;
    }
    if (!input || typeof input !== 'object' || Array.isArray(input) || input.termsAccepted !== true) {
        sendJson(response, 400, { error: 'Please provide valid details and accept the terms.' });
        return;
    }
    const fullName = typeof input.fullName === 'string' ? input.fullName.trim() : '';
    const email = typeof input.email === 'string' ? input.email.trim().toLowerCase() : '';
    const username = typeof input.username === 'string' ? input.username.trim() : '';
    const password = typeof input.password === 'string' ? input.password : '';
    if (!fullName || fullName.length > 100 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254 || !/^[a-zA-Z0-9_.-]{4,40}$/.test(username)) {
        sendJson(response, 400, { error: 'Enter a valid name, email, and username (4–40 letters, numbers, dots, underscores, or hyphens).' });
        return;
    }
    if (password.length < 6 || Buffer.byteLength(password, 'utf8') > 1024) {
        sendJson(response, 400, { error: 'Password must be 6–1024 bytes.' });
        return;
    }
    try {
        const passwordHash = await hashPassword(password);
        db.prepare('INSERT INTO students (full_name, email, username, password_hash) VALUES (?, ?, ?, ?)')
            .run(fullName, email, username, passwordHash);
        sendJson(response, 201, { message: 'Student account created successfully.' });
    } catch (error) {
        if (/UNIQUE constraint failed/i.test(error.message)) {
            sendJson(response, 409, { error: 'That email address or username is already registered.' });
            return;
        }
        console.error('Student signup error:', error);
        sendJson(response, 500, { error: 'Could not create the student account.' });
    }
}

async function loginStudent(request, response) {
    let input;
    try {
        input = await readJsonBody(request);
    } catch (error) {
        sendJson(response, 400, { error: error.message });
        return;
    }
    if (!input || typeof input !== 'object' || Array.isArray(input)) {
        sendJson(response, 400, { error: 'Please send valid login details.' });
        return;
    }
    const identifier = typeof input.identifier === 'string' ? input.identifier.trim() : '';
    const password = typeof input.password === 'string' ? input.password : '';
    if (!identifier || !password || identifier.length > 254 || Buffer.byteLength(password, 'utf8') > 1024) {
        sendJson(response, 400, { error: 'Enter a valid email/username and password.' });
        return;
    }
    const student = db.prepare(`SELECT id, username, full_name, password_hash, status FROM students
        WHERE username = ? COLLATE NOCASE OR email = ? COLLATE NOCASE`).get(identifier, identifier);
    const valid = student ? await verifyPassword(password, student.password_hash) : false;
    if (!valid) {
        sendJson(response, 401, { error: 'Incorrect username/email or password.' });
        return;
    }
    if (student.status === 'blocked') {
        sendJson(response, 403, { error: 'Your student account is blocked. Contact the administrator.' });
        return;
    }
    const token = randomBytes(32).toString('hex');
    const maxAge = input.remember === true ? 60 * 60 * 24 * 30 : undefined;
    sessions.set(token, { role: 'student', studentId: student.id, expiresAt: Date.now() + (maxAge || 8 * 60 * 60) * 1000 });
    setSessionCookie(response, 'student', token, maxAge);
    sendJson(response, 200, { message: 'Login successful.', username: student.username, fullName: student.full_name });
}

const server = http.createServer(async (request, response) => {
    const url = new URL(request.url, `http://${request.headers.host || 'localhost'}`);
    url.pathname = url.pathname.replace(/\/+$/, '') || '/';

    const adminSession = getSession(request, 'admin');
    const studentSession = getSession(request, 'student');

    if (url.pathname === '/api/student/signup' && request.method === 'POST') {
        createStudent(request, response);
        return;
    }
    if (url.pathname === '/api/student/login' && request.method === 'POST') {
        loginStudent(request, response);
        return;
    }
    if (url.pathname === '/api/admin/logout' || url.pathname === '/api/student/logout') {
        const role = url.pathname.includes('/admin/') ? 'admin' : 'student';
        const token = readCookie(request, `exampro_${role}_session`);
        if (token) sessions.delete(token);
        response.setHeader('Set-Cookie', `exampro_${role}_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0`);
        sendJson(response, 200, { message: 'Logged out.' });
        return;
    }

    // Public password reset API (no auth required)
    if (url.pathname === '/api/admin/password-reset' && request.method === 'POST') {
        await handlePasswordResetRequest(request, response);
        return;
    }
    if (url.pathname === '/api/admin/password-reset/verify' && request.method === 'POST') {
        await handlePasswordResetVerify(request, response);
        return;
    }
    if (url.pathname === '/api/admin/password-reset/complete' && request.method === 'POST') {
        await handlePasswordResetComplete(request, response);
        return;
    }

    if (url.pathname === '/api/admin/announcements') {
        if (!adminSession) {
            sendJson(response, 401, { error: 'Please log in as an administrator.' });
            return;
        }
        if (request.method === 'GET') {
            return sendJson(response, 200, db.prepare(`SELECT id, title, message, created_at AS createdAt
                FROM announcements ORDER BY created_at DESC, id DESC`).all());
        }
        if (request.method === 'POST') {
            try {
                const input = await readJsonBody(request);
                if (!input || typeof input !== 'object' || Array.isArray(input)) {
                    return sendJson(response, 400, { error: 'Provide an announcement title and message.' });
                }
                const title = typeof input.title === 'string' ? input.title.trim() : '';
                const message = typeof input.message === 'string' ? input.message.trim() : '';
                if (!title || title.length > 120 || !message || message.length > 2000) {
                    return sendJson(response, 400, { error: 'Title is required (max 120 characters) and message is required (max 2000 characters).' });
                }
                const result = db.prepare('INSERT INTO announcements (title, message) VALUES (?, ?)').run(title, message);
                return sendJson(response, 201, { id: Number(result.lastInsertRowid), message: 'Announcement published.' });
            } catch (error) {
                return sendJson(response, 400, { error: error.message || 'Invalid announcement data.' });
            }
        }
        response.setHeader('Allow', 'GET, POST');
        return sendJson(response, 405, { error: 'Method not allowed.' });
    }

    const announcementDeletePath = url.pathname.match(/^\/api\/admin\/announcements\/(\d+)$/);
    if (announcementDeletePath) {
        if (!adminSession) {
            sendJson(response, 401, { error: 'Please log in as an administrator.' });
            return;
        }
        if (request.method !== 'DELETE') {
            response.setHeader('Allow', 'DELETE');
            return sendJson(response, 405, { error: 'Method not allowed.' });
        }
        const result = db.prepare('DELETE FROM announcements WHERE id = ?').run(Number(announcementDeletePath[1]));
        if (!result.changes) return sendJson(response, 404, { error: 'Announcement not found.' });
        return sendJson(response, 200, { message: 'Announcement deleted.' });
    }

    if (url.pathname.startsWith('/api/admin/')) {
        if (request.method !== 'GET' && request.method !== 'POST' && request.method !== 'PATCH' && request.method !== 'DELETE') {
            response.setHeader('Allow', 'GET, POST, PATCH, DELETE');
            sendJson(response, 405, { error: 'Method not allowed.' });
            return;
        }
        if (url.pathname === '/api/admin/login' && request.method === 'POST') {
            loginAdmin(request, response);
            return;
        }
        if (url.pathname === '/api/admin/signup' && request.method === 'POST') {
            createAdmin(request, response);
            return;
        }
        if (!adminSession) {
            sendJson(response, 401, { error: 'Please log in as an administrator.' });
            return;
        }

        try {
            if (url.pathname === '/api/admin/me' && request.method === 'GET') {
                const profile = db.prepare('SELECT id, full_name AS fullName, email, username FROM admins WHERE id = ?').get(adminSession.adminId);
                if (!profile) return sendJson(response, 401, { error: 'Admin account not found.' });
                return sendJson(response, 200, profile);
            }
            if (url.pathname === '/api/admin/me' && request.method === 'PATCH') {
                const input = await readJsonBody(request);
                const fullName = typeof input.fullName === 'string' ? input.fullName.trim() : '';
                const email = typeof input.email === 'string' ? input.email.trim().toLowerCase() : '';
                const username = typeof input.username === 'string' ? input.username.trim() : '';
                if (!fullName || fullName.length > 100 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254 || !/^[a-zA-Z0-9_.-]{3,40}$/.test(username)) {
                    return sendJson(response, 400, { error: 'Enter a valid name, email, and username.' });
                }
                db.prepare('UPDATE admins SET full_name = ?, email = ?, username = ? WHERE id = ?').run(fullName, email, username, adminSession.adminId);
                return sendJson(response, 200, { message: 'Profile updated.' });
            }
            if (url.pathname === '/api/admin/password' && request.method === 'POST') {
                const input = await readJsonBody(request);
                const currentPassword = typeof input.currentPassword === 'string' ? input.currentPassword : '';
                const newPassword = typeof input.newPassword === 'string' ? input.newPassword : '';
                const confirmPassword = typeof input.confirmPassword === 'string' ? input.confirmPassword : '';
                if (!currentPassword || !newPassword || !confirmPassword) {
                    return sendJson(response, 400, { error: 'Fill in all password fields.' });
                }
                if (Buffer.byteLength(currentPassword, 'utf8') > 1024 || Buffer.byteLength(newPassword, 'utf8') > 1024) {
                    return sendJson(response, 400, { error: 'Password is too long.' });
                }
                if (newPassword.length < 8) {
                    return sendJson(response, 400, { error: 'Your new password must be at least 8 characters.' });
                }
                if (newPassword !== confirmPassword) {
                    return sendJson(response, 400, { error: 'The new passwords do not match.' });
                }
                const admin = db.prepare('SELECT password_hash FROM admins WHERE id = ?').get(adminSession.adminId);
                if (!admin || !(await verifyPassword(currentPassword, admin.password_hash))) {
                    return sendJson(response, 400, { error: 'Your current password is incorrect.' });
                }
                const passwordHash = await hashPassword(newPassword);
                db.prepare('UPDATE admins SET password_hash = ? WHERE id = ?').run(passwordHash, adminSession.adminId);
                return sendJson(response, 200, { message: 'Admin password changed successfully.' });
            }
            if (url.pathname === '/api/admin/students' && request.method === 'GET') {
                const students = db.prepare(`SELECT id, full_name AS fullName, email, username, status, created_at AS createdAt
                    FROM students ORDER BY created_at DESC, id DESC`).all();
                return sendJson(response, 200, students);
            }
            const studentStatus = url.pathname.match(/^\/api\/admin\/students\/(\d+)\/status$/);
            if (studentStatus && request.method === 'PATCH') {
                const input = await readJsonBody(request);
                if (!['active', 'blocked'].includes(input.status)) return sendJson(response, 400, { error: 'Status must be active or blocked.' });
                const result = db.prepare('UPDATE students SET status = ? WHERE id = ?').run(input.status, Number(studentStatus[1]));
                if (!result.changes) return sendJson(response, 404, { error: 'Student not found.' });
                return sendJson(response, 200, { message: `Student ${input.status === 'blocked' ? 'blocked' : 'unblocked'}.` });
            }
            if (url.pathname === '/api/admin/subjects' && request.method === 'GET') {
                return sendJson(response, 200, db.prepare(`SELECT s.id, s.name, s.code, s.created_at AS createdAt,
                    COUNT(q.id) AS questionCount FROM subjects s LEFT JOIN questions q ON q.subject_id = s.id
                    GROUP BY s.id ORDER BY s.name`).all());
            }
            if (url.pathname === '/api/admin/subjects' && request.method === 'POST') {
                const input = await readJsonBody(request);
                const name = typeof input.name === 'string' ? input.name.trim() : '';
                const code = typeof input.code === 'string' ? input.code.trim().toUpperCase() : '';
                if (!name || name.length > 80 || !/^[A-Z0-9_-]{2,20}$/.test(code)) return sendJson(response, 400, { error: 'Enter a subject name and a code (2–20 letters, numbers, _ or -).' });
                const result = db.prepare('INSERT INTO subjects (name, code) VALUES (?, ?)').run(name, code);
                createStudentAnnouncement('New subject added', `${name} (${code}) is now available in your dashboard.`);
                return sendJson(response, 201, { id: Number(result.lastInsertRowid), message: 'Subject created.' });
            }
            const subjectPath = url.pathname.match(/^\/api\/admin\/subjects\/(\d+)$/);
            if (subjectPath && request.method === 'DELETE') {
                const subject = db.prepare('SELECT name, code FROM subjects WHERE id = ?').get(Number(subjectPath[1]));
                const result = db.prepare('DELETE FROM subjects WHERE id = ?').run(Number(subjectPath[1]));
                if (!result.changes) return sendJson(response, 404, { error: 'Subject not found.' });
                createStudentAnnouncement('Subject removed', `${subject?.name || 'A subject'} was removed from the student dashboard.`);
                return sendJson(response, 200, { message: 'Subject deleted.' });
            }
            if (url.pathname === '/api/admin/questions' && request.method === 'GET') {
                return sendJson(response, 200, db.prepare(`SELECT q.id, q.subject_id AS subjectId, s.name AS subject,
                    q.prompt, q.choices, q.correct_answer AS correctAnswer, q.created_at AS createdAt
                    FROM questions q JOIN subjects s ON s.id = q.subject_id ORDER BY q.created_at DESC, q.id DESC`).all()
                    .map(question => ({ ...question, choices: JSON.parse(question.choices) })));
            }
            if (url.pathname === '/api/admin/questions' && request.method === 'POST') {
                const input = await readJsonBody(request);
                const subjectId = Number(input.subjectId);
                const prompt = typeof input.prompt === 'string' ? input.prompt.trim() : '';
                const choices = input.choices;
                const correctAnswer = Number(input.correctAnswer);
                if (!Number.isInteger(subjectId) || !prompt || prompt.length > 2000 || !Array.isArray(choices) || choices.length < 2 || choices.length > 6 || choices.some(choice => typeof choice !== 'string' || !choice.trim() || choice.length > 300) || !Number.isInteger(correctAnswer) || correctAnswer < 0 || correctAnswer >= choices.length) {
                    return sendJson(response, 400, { error: 'Provide a subject, question, 2–6 choices, and select the correct choice.' });
                }
                const result = db.prepare('INSERT INTO questions (subject_id, prompt, choices, correct_answer) VALUES (?, ?, ?, ?)').run(subjectId, prompt, JSON.stringify(choices.map(choice => choice.trim())), correctAnswer);
                const subject = db.prepare('SELECT name FROM subjects WHERE id = ?').get(subjectId);
                createStudentAnnouncement('New exam question added', `A new question was added to ${subject?.name || 'a subject'}.`);
                return sendJson(response, 201, { id: Number(result.lastInsertRowid), message: 'Question saved.' });
            }
            const questionPath = url.pathname.match(/^\/api\/admin\/questions\/(\d+)$/);
            if (questionPath && request.method === 'DELETE') {
                const question = db.prepare(`SELECT s.name AS subject FROM questions q JOIN subjects s ON s.id = q.subject_id WHERE q.id = ?`).get(Number(questionPath[1]));
                const result = db.prepare('DELETE FROM questions WHERE id = ?').run(Number(questionPath[1]));
                if (!result.changes) return sendJson(response, 404, { error: 'Question not found.' });
                createStudentAnnouncement('Exam question updated', `A question was removed from ${question?.subject || 'a subject'}.`);
                return sendJson(response, 200, { message: 'Question deleted.' });
            }
            if (url.pathname === '/api/admin/results' && request.method === 'GET') {
                return sendJson(response, 200, db.prepare(`SELECT r.id, st.full_name AS studentName, st.username,
                    st.email, COALESCE(s.name, 'Deleted subject') AS subject, r.score, r.total,
                    r.submitted_at AS submittedAt FROM results r JOIN students st ON st.id = r.student_id
                    LEFT JOIN subjects s ON s.id = r.subject_id ORDER BY r.submitted_at DESC, r.id DESC`).all());
            }
            if (url.pathname === '/api/admin/summary' && request.method === 'GET') {
                return sendJson(response, 200, {
                    students: db.prepare('SELECT COUNT(*) AS count FROM students').get().count,
                    activeStudents: db.prepare("SELECT COUNT(*) AS count FROM students WHERE status = 'active'").get().count,
                    subjects: db.prepare('SELECT COUNT(*) AS count FROM subjects').get().count,
                    questions: db.prepare('SELECT COUNT(*) AS count FROM questions').get().count,
                    results: db.prepare('SELECT COUNT(*) AS count FROM results').get().count
                });
            }
        } catch (error) {
            if (/UNIQUE constraint failed/i.test(error.message)) return sendJson(response, 409, { error: 'That value already exists.' });
            if (error instanceof SyntaxError) return sendJson(response, 400, { error: 'Invalid request data.' });
            console.error('Admin API error:', error);
            return sendJson(response, 500, { error: 'Could not complete that request.' });
        }
        sendJson(response, 404, { error: 'Admin API endpoint not found.' });
        return;
    }

    if (url.pathname === '/api/student/me' && request.method === 'GET') {
        if (!studentSession) return sendJson(response, 401, { error: 'Please log in as a student.' });
        const student = db.prepare('SELECT id, full_name AS fullName, username, email, status FROM students WHERE id = ?').get(studentSession.studentId);
        if (!student || student.status === 'blocked') return sendJson(response, 403, { error: 'Student account is blocked.' });
        return sendJson(response, 200, student);
    }

    if (url.pathname === '/api/student/me' && request.method === 'PATCH') {
        if (!studentSession) return sendJson(response, 401, { error: 'Please log in as a student.' });
        const student = db.prepare('SELECT status FROM students WHERE id = ?').get(studentSession.studentId);
        if (!student || student.status === 'blocked') return sendJson(response, 403, { error: 'Student account is blocked.' });
        const input = await readJsonBody(request);
        const fullName = typeof input.fullName === 'string' ? input.fullName.trim() : '';
        const email = typeof input.email === 'string' ? input.email.trim().toLowerCase() : '';
        const username = typeof input.username === 'string' ? input.username.trim() : '';
        if (!fullName || fullName.length > 100 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254 || !/^[a-zA-Z0-9_.-]{3,40}$/.test(username)) {
            return sendJson(response, 400, { error: 'Enter a valid name, email, and username.' });
        }
        const result = db.prepare('UPDATE students SET full_name = ?, email = ?, username = ? WHERE id = ?').run(fullName, email, username, studentSession.studentId);
        if (!result.changes) return sendJson(response, 404, { error: 'Student not found.' });
        return sendJson(response, 200, { message: 'Profile updated.' });
    }

    if (url.pathname === '/api/student/password' && request.method === 'POST') {
        if (!studentSession) return sendJson(response, 401, { error: 'Please log in as a student.' });
        const student = db.prepare('SELECT status, password_hash FROM students WHERE id = ?').get(studentSession.studentId);
        if (!student || student.status === 'blocked') return sendJson(response, 403, { error: 'Student account is blocked.' });
        const input = await readJsonBody(request);
        const currentPassword = typeof input.currentPassword === 'string' ? input.currentPassword : '';
        const newPassword = typeof input.newPassword === 'string' ? input.newPassword : '';
        const confirmPassword = typeof input.confirmPassword === 'string' ? input.confirmPassword : '';
        if (!currentPassword || !newPassword || !confirmPassword) {
            return sendJson(response, 400, { error: 'Fill in all password fields.' });
        }
        if (Buffer.byteLength(currentPassword, 'utf8') > 1024 || Buffer.byteLength(newPassword, 'utf8') > 1024) {
            return sendJson(response, 400, { error: 'Password is too long.' });
        }
        if (newPassword.length < 8) {
            return sendJson(response, 400, { error: 'Your new password must be at least 8 characters.' });
        }
        if (newPassword !== confirmPassword) {
            return sendJson(response, 400, { error: 'The new passwords do not match.' });
        }
        if (!(await verifyPassword(currentPassword, student.password_hash))) {
            return sendJson(response, 400, { error: 'Your current password is incorrect.' });
        }
        const passwordHash = await hashPassword(newPassword);
        db.prepare('UPDATE students SET password_hash = ? WHERE id = ?').run(passwordHash, studentSession.studentId);
        return sendJson(response, 200, { message: 'Password changed successfully.' });
    }

    if (url.pathname === '/api/student/announcements' && request.method === 'GET') {
        if (!studentSession) return sendJson(response, 401, { error: 'Please log in as a student.' });
        const student = db.prepare('SELECT status FROM students WHERE id = ?').get(studentSession.studentId);
        if (!student || student.status !== 'active') return sendJson(response, 403, { error: 'Student account is not active.' });
        return sendJson(response, 200, db.prepare(`SELECT id, title, message, created_at AS createdAt
            FROM announcements ORDER BY created_at DESC, id DESC`).all());
    }

    if (url.pathname === '/api/student/subjects' && request.method === 'GET') {
        if (!studentSession) return sendJson(response, 401, { error: 'Please log in as a student.' });
        const student = db.prepare('SELECT status FROM students WHERE id = ?').get(studentSession.studentId);
        if (!student || student.status !== 'active') return sendJson(response, 403, { error: 'Student account is not active.' });
        return sendJson(response, 200, db.prepare(`SELECT s.id, s.name, s.code, s.created_at AS createdAt,
            COUNT(q.id) AS questionCount FROM subjects s LEFT JOIN questions q ON q.subject_id = s.id
            GROUP BY s.id ORDER BY s.name`).all());
    }

    if (url.pathname === '/api/student/results' && request.method === 'GET') {
        if (!studentSession) return sendJson(response, 401, { error: 'Please log in as a student.' });
        const student = db.prepare('SELECT status FROM students WHERE id = ?').get(studentSession.studentId);
        if (!student || student.status !== 'active') return sendJson(response, 403, { error: 'Student account is not active.' });
        return sendJson(response, 200, db.prepare(`SELECT r.id, COALESCE(s.name, 'Deleted subject') AS subject,
            r.score, r.total, r.submitted_at AS submittedAt FROM results r
            LEFT JOIN subjects s ON s.id = r.subject_id WHERE r.student_id = ?
            ORDER BY r.submitted_at DESC, r.id DESC`).all(studentSession.studentId));
    }

    const studentExamPath = url.pathname.match(/^\/api\/student\/exams\/(\d+)$/);
    if (studentExamPath && request.method === 'GET') {
        if (!studentSession) return sendJson(response, 401, { error: 'Please log in as a student.' });
        const student = db.prepare('SELECT status FROM students WHERE id = ?').get(studentSession.studentId);
        if (!student || student.status !== 'active') return sendJson(response, 403, { error: 'Student account is not active.' });
        const subjectId = Number(studentExamPath[1]);
        const subject = db.prepare('SELECT id, name, code FROM subjects WHERE id = ?').get(subjectId);
        if (!subject) return sendJson(response, 404, { error: 'Subject not found.' });
        const questions = db.prepare(`SELECT id, prompt, choices FROM questions
            WHERE subject_id = ? ORDER BY id`).all(subjectId)
            .map(question => ({ id: question.id, prompt: question.prompt, choices: JSON.parse(question.choices) }));
        if (!questions.length) return sendJson(response, 404, { error: 'There are no questions for this exam yet.' });
        return sendJson(response, 200, { subject, questions });
    }

    if (url.pathname === '/api/student/exams/submit' && request.method === 'POST') {
        if (!studentSession) return sendJson(response, 401, { error: 'Please log in as a student.' });
        const student = db.prepare('SELECT status FROM students WHERE id = ?').get(studentSession.studentId);
        if (!student || student.status !== 'active') return sendJson(response, 403, { error: 'Student account is not active.' });
        let input;
        try {
            input = await readJsonBody(request);
        } catch (error) {
            return sendJson(response, 400, { error: error.message });
        }
        const subjectId = Number(input?.subjectId);
        const answers = input?.answers;
        if (!Number.isInteger(subjectId) || subjectId < 1 || !Array.isArray(answers)) {
            return sendJson(response, 400, { error: 'Please submit valid exam answers.' });
        }
        const questions = db.prepare('SELECT id, correct_answer FROM questions WHERE subject_id = ? ORDER BY id').all(subjectId);
        if (!questions.length) return sendJson(response, 404, { error: 'There are no questions for this exam.' });
        if (answers.length !== questions.length) return sendJson(response, 400, { error: 'Please answer every question before submitting.' });
        const answerMap = new Map();
        for (const answer of answers) {
            const questionId = Number(answer?.questionId);
            const selectedAnswer = Number(answer?.selectedAnswer);
            if (!Number.isInteger(questionId) || !Number.isInteger(selectedAnswer) || answerMap.has(questionId)) {
                return sendJson(response, 400, { error: 'The submitted answers are invalid.' });
            }
            answerMap.set(questionId, selectedAnswer);
        }
        if (questions.some(question => !answerMap.has(question.id))) {
            return sendJson(response, 400, { error: 'Please answer every question before submitting.' });
        }
        const score = questions.reduce((total, question) => total + (answerMap.get(question.id) === question.correct_answer ? 1 : 0), 0);
        try {
            const result = db.prepare(`INSERT INTO results (student_id, subject_id, score, total)
                VALUES (?, ?, ?, ?)`).run(studentSession.studentId, subjectId, score, questions.length);
            return sendJson(response, 201, {
                id: Number(result.lastInsertRowid),
                score,
                total: questions.length,
                message: 'Exam submitted successfully.'
            });
        } catch (error) {
            console.error('Student exam submission error:', error);
            return sendJson(response, 500, { error: 'Could not save your exam result.' });
        }
    }

    if (url.pathname === '/api/admin/signup') {
        if (request.method !== 'POST') {
            response.setHeader('Allow', 'POST');
            sendJson(response, 405, { error: 'Method not allowed.' });
            return;
        }
        createAdmin(request, response);
        return;
    }

    if (url.pathname === '/api/admin/login') {
        if (request.method !== 'POST') {
            response.setHeader('Allow', 'POST');
            sendJson(response, 405, { error: 'Method not allowed.' });
            return;
        }
        loginAdmin(request, response);
        return;
    }

    // Password reset API
    if (url.pathname === '/api/admin/password-reset' && request.method === 'POST') {
        return handlePasswordResetRequest(request, response);
    }
    if (url.pathname === '/api/admin/password-reset/verify' && request.method === 'POST') {
        return handlePasswordResetVerify(request, response);
    }
    if (url.pathname === '/api/admin/password-reset/complete' && request.method === 'POST') {
        return handlePasswordResetComplete(request, response);
    }

    if (request.method !== 'GET' && request.method !== 'HEAD') {
        sendJson(response, 404, { error: 'Not found.' });
        return;
    }

    const requestedPage = url.pathname === '/' ? 'home.html' : decodeURIComponent(url.pathname.slice(1));
    if (!allowedPages.has(requestedPage)) {
        response.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
        response.end('Page not found.');
        return;
    }

    if (requestedPage === 'admin_dashbroad.html') {
        if (!adminSession) {
            response.writeHead(302, { Location: '/adminlogin.html', 'Cache-Control': 'no-store' });
            response.end();
            return;
        }
    }
    if (requestedPage === 'student_dashboard.html') {
        if (!studentSession) {
            response.writeHead(302, { Location: '/login.html', 'Cache-Control': 'no-store' });
            response.end();
            return;
        }
        const student = db.prepare('SELECT status FROM students WHERE id = ?').get(studentSession.studentId);
        if (!student || student.status === 'blocked') {
            const token = readCookie(request, 'exampro_student_session');
            if (token) sessions.delete(token);
            response.writeHead(302, {
                Location: '/login.html',
                'Set-Cookie': 'exampro_student_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0',
                'Cache-Control': 'no-store'
            });
            response.end();
            return;
        }
    }

    const filePath = path.join(ROOT, requestedPage);
    fs.readFile(filePath, (error, content) => {
        if (error) {
            response.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
            response.end('Page not found.');
            return;
        }
        response.writeHead(200, {
            'Content-Type': 'text/html; charset=utf-8',
            'X-Content-Type-Options': 'nosniff'
        });
        response.end(request.method === 'HEAD' ? undefined : content);
    });
});

function listenOnAvailablePort(port) {
    server.once('error', error => {
        if (error.code === 'EADDRINUSE' && port < PORT + 20) {
            console.warn(`Port ${port} is already in use; trying port ${port + 1}.`);
            listenOnAvailablePort(port + 1);
            return;
        }
        console.error('Could not start ExamPro server:', error.message);
        process.exitCode = 1;
    });
    server.listen(port, '0.0.0.0', () => {
        const activePort = server.address().port;
        console.log(`ExamPro is running at http://localhost:${activePort}/adminsignup.html`);
        console.log(`You can also use http://127.0.0.1:${activePort}/adminsignup.html or this device's local IP address.`);
        console.log(`SQLite database: ${DB_PATH}`);
    });
}

listenOnAvailablePort(PORT);
