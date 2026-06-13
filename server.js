const express      = require('express');
const Database     = require('better-sqlite3');
const multer       = require('multer');
const cloudinary   = require('cloudinary').v2;
const streamifier  = require('streamifier');
const bcrypt       = require('bcryptjs');
const helmet       = require('helmet');
const rateLimit    = require('express-rate-limit');
const path         = require('path');
const fs           = require('fs');
const https        = require('https');
const http         = require('http');
const session      = require('express-session');

const app  = express();
const PORT = process.env.PORT || 3000;

// ── SECURITY HEADERS (helmet) ──────────────────────────────────────────────
// Protects against XSS, clickjacking, sniffing attacks, etc.
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc:   ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc:    ["'self'", "https://fonts.gstatic.com"],
      scriptSrc:  ["'self'", "'unsafe-inline'"],
      imgSrc:     ["'self'", "data:", "https://res.cloudinary.com", "blob:"],
      frameSrc:   ["'self'"],
    },
  },
  crossOriginEmbedderPolicy: false, // needed for PDF iframe
}));

// ── RATE LIMITING ──────────────────────────────────────────────────────────
// Prevents brute-force login attacks
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10,                   // max 10 login attempts per 15 min per IP
  message: { error: 'Too many login attempts. Please wait 15 minutes.' },
  standardHeaders: true,
  legacyHeaders: false,
});

// Prevents upload abuse
const uploadLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 50,                   // max 50 uploads per hour per IP
  message: { error: 'Too many uploads. Please wait an hour.' },
});

// General API limit
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 300,
  message: { error: 'Too many requests.' },
});

app.use('/api/', apiLimiter);

// ── CLOUDINARY ─────────────────────────────────────────────────────────────
// Keys come ONLY from environment variables — never hardcoded
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key:    process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

const cloudinaryReady = !!(
  process.env.CLOUDINARY_CLOUD_NAME &&
  process.env.CLOUDINARY_API_KEY &&
  process.env.CLOUDINARY_API_SECRET
);

console.log(cloudinaryReady
  ? '☁️  Cloudinary connected.'
  : '💾 No Cloudinary — saving locally.');

function uploadToCloudinary(buffer, options) {
  return new Promise((resolve, reject) => {
    const stream = cloudinary.uploader.upload_stream(options, (err, result) => {
      if (err) reject(err);
      else resolve({ url: result.secure_url, public_id: result.public_id });
    });
    streamifier.createReadStream(buffer).pipe(stream);
  });
}

function saveLocally(buffer, filename) {
  const safe = Date.now() + '-' + filename.replace(/[^a-zA-Z0-9.\-_]/g, '_');
  fs.writeFileSync(path.join(__dirname, 'uploads', safe), buffer);
  return { url: '/uploads/' + safe, public_id: null };
}

async function storeFile(file, type) {
  if (!file) return { url: null, public_id: null };
  if (cloudinaryReady) {
    if (type === 'pdf') {
      const result = await uploadToCloudinary(file.buffer, {
        folder: 'maktaba/pdfs',
        resource_type: 'raw',
        public_id: 'pdf_' + Date.now() + '.pdf',
      });
      return { url: result.url, public_id: result.public_id };
    }
    return uploadToCloudinary(file.buffer, {
      folder: 'maktaba/images',
      resource_type: 'image',
      transformation: [{ width: 600, crop: 'limit', quality: 'auto' }],
    });
  }
  return saveLocally(file.buffer, file.originalname);
}

async function deleteFile(public_id, url, resource_type) {
  const rtype = resource_type || 'image';
  if (cloudinaryReady && public_id) {
    try { await cloudinary.uploader.destroy(public_id, { resource_type: rtype }); } catch(e) {}
  } else if (url && url.startsWith('/uploads/')) {
    const f = path.join(__dirname, url);
    if (fs.existsSync(f)) try { fs.unlinkSync(f); } catch(e) {}
  }
}

// ── DATABASE ───────────────────────────────────────────────────────────────
if (!fs.existsSync('uploads')) fs.mkdirSync('uploads');

const db = new Database('maktaba.db');

db.exec(`
  CREATE TABLE IF NOT EXISTS books (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL, author TEXT NOT NULL, genre TEXT NOT NULL,
    emoji TEXT DEFAULT '📖', description TEXT,
    cover_url TEXT, cover_public_id TEXT,
    pdf_name TEXT, pdf_url TEXT, pdf_public_id TEXT,
    is_new INTEGER DEFAULT 1,
    created_at TEXT DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS authors (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE, bio TEXT,
    photo_url TEXT, photo_public_id TEXT, website TEXT,
    created_at TEXT DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS admins (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL
  );
`);

// Create default admin with HASHED password if not exists
const existingAdmin = db.prepare('SELECT id FROM admins WHERE email=?').get('admin@library.com');
if (!existingAdmin) {
  // Use ADMIN_PASSWORD env var if set, otherwise use default
  const rawPassword = process.env.ADMIN_PASSWORD || 'admin123';
  const hashed = bcrypt.hashSync(rawPassword, 12);
  db.prepare('INSERT INTO admins (email,password) VALUES (?,?)').run('admin@library.com', hashed);
  console.log('✅ Admin created. Password:', rawPassword === 'admin123'
    ? 'admin123 (⚠️  CHANGE THIS — set ADMIN_PASSWORD env var)'
    : '(from ADMIN_PASSWORD env var)');
}

console.log('✅ Database ready.');

// ── MULTER — file type validation + size limits ────────────────────────────
const memUpload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 50 * 1024 * 1024 }, // 50MB max
  fileFilter: (req, file, cb) => {
    const allowed = ['application/pdf', 'image/jpeg', 'image/png', 'image/webp', 'image/gif'];
    if (allowed.includes(file.mimetype)) cb(null, true);
    else cb(new Error('Only PDF and image files are allowed'));
  }
});

// ── MIDDLEWARE ─────────────────────────────────────────────────────────────
app.use(express.json({ limit: '1mb' }));        // prevent huge JSON payloads
app.use(express.urlencoded({ extended: true, limit: '1mb' }));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
  secret: process.env.SESSION_SECRET || (() => {
    console.warn('⚠️  SESSION_SECRET not set — using insecure default. Set it in env vars!');
    return 'maktaba-default-insecure-secret';
  })(),
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 24 * 60 * 60 * 1000,
    httpOnly: true,   // JS can't read the cookie
    secure: process.env.NODE_ENV === 'production', // HTTPS only in prod
    sameSite: 'lax',  // CSRF protection
  }
}));

function requireAdmin(req, res, next) {
  if (req.session?.admin) return next();
  res.status(401).json({ error: 'Not authenticated' });
}

// ── AUTH ───────────────────────────────────────────────────────────────────
app.post('/api/login', loginLimiter, (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
    // Sanitize input length
    if (email.length > 200 || password.length > 200)
      return res.status(400).json({ error: 'Invalid input' });
    const admin = db.prepare('SELECT * FROM admins WHERE email=?').get(email.trim().toLowerCase());
    // Use bcrypt compare — constant time, prevents timing attacks
    if (!admin || !bcrypt.compareSync(password, admin.password))
      return res.status(401).json({ error: 'Invalid email or password' });
    req.session.admin = { id: admin.id, email: admin.email };
    res.json({ success: true, email: admin.email });
  } catch(e) { res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/logout', (req, res) => { req.session.destroy(); res.json({ success: true }); });
app.get('/api/me', (req, res) => res.json({ admin: req.session?.admin || null }));

// Change password (admin only)
app.post('/api/change-password', requireAdmin, (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    if (!currentPassword || !newPassword) return res.status(400).json({ error: 'Both fields required' });
    if (newPassword.length < 8) return res.status(400).json({ error: 'New password must be at least 8 characters' });
    const admin = db.prepare('SELECT * FROM admins WHERE id=?').get(req.session.admin.id);
    if (!bcrypt.compareSync(currentPassword, admin.password))
      return res.status(401).json({ error: 'Current password is incorrect' });
    const hashed = bcrypt.hashSync(newPassword, 12);
    db.prepare('UPDATE admins SET password=? WHERE id=?').run(hashed, admin.id);
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: 'Server error' }); }
});

// ── BOOKS ──────────────────────────────────────────────────────────────────
app.get('/api/books', (req, res) => {
  try {
    const { q, genre, author_id } = req.query;
    let sql = 'SELECT * FROM books WHERE 1=1'; const params = [];
    if (q) {
      sql += ' AND (lower(title) LIKE lower(?) OR lower(author) LIKE lower(?) OR lower(genre) LIKE lower(?))';
      const like = '%' + q.slice(0,100) + '%'; params.push(like,like,like);
    }
    if (genre) { sql += ' AND lower(genre)=lower(?)'; params.push(genre.slice(0,50)); }
    if (author_id) {
      const a = db.prepare('SELECT name FROM authors WHERE id=?').get(author_id);
      if (a) { sql += ' AND lower(author)=lower(?)'; params.push(a.name); }
    }
    res.json(db.prepare(sql + ' ORDER BY created_at DESC').all(...params));
  } catch(e) { res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/books', requireAdmin, uploadLimiter, memUpload.fields([{name:'cover',maxCount:1},{name:'pdf',maxCount:1}]), async (req, res) => {
  try {
    const { title, author, genre, emoji, description } = req.body;
    if (!title || !author) return res.status(400).json({ error: 'Title and author are required' });
    const cover = await storeFile(req.files?.cover?.[0], 'image');
    const pdf   = await storeFile(req.files?.pdf?.[0],   'pdf');
    const result = db.prepare(
      `INSERT INTO books (title,author,genre,emoji,description,cover_url,cover_public_id,pdf_name,pdf_url,pdf_public_id,is_new) VALUES (?,?,?,?,?,?,?,?,?,?,1)`
    ).run(
      title.slice(0,200), author.slice(0,200), (genre||'Other').slice(0,50),
      (emoji||'📖').slice(0,10), (description||'').slice(0,1000),
      cover.url, cover.public_id,
      req.files?.pdf?.[0]?.originalname?.slice(0,200)||null, pdf.url, pdf.public_id
    );
    res.json(db.prepare('SELECT * FROM books WHERE id=?').get(result.lastInsertRowid));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/books/bulk', requireAdmin, (req, res) => {
  try {
    const { books } = req.body;
    if (!Array.isArray(books) || !books.length) return res.status(400).json({ error: 'No books provided' });
    if (books.length > 200) return res.status(400).json({ error: 'Max 200 books per import' });
    let added = 0;
    const stmt = db.prepare(`INSERT INTO books (title,author,genre,emoji,description,is_new) VALUES (?,?,?,?,?,1)`);
    for (const b of books) {
      if (!b.title || !b.author) continue;
      stmt.run(b.title.trim().slice(0,200), b.author.trim().slice(0,200),
        (b.genre||'Other').slice(0,50), (b.emoji||'📖').slice(0,10), (b.description||'').slice(0,1000));
      added++;
    }
    res.json({ success: true, added });
  } catch(e) { res.status(500).json({ error: 'Server error' }); }
});

app.put('/api/books/:id', requireAdmin, uploadLimiter, memUpload.fields([{name:'cover',maxCount:1},{name:'pdf',maxCount:1}]), async (req, res) => {
  try {
    const existing = db.prepare('SELECT * FROM books WHERE id=?').get(req.params.id);
    if (!existing) return res.status(404).json({ error: 'Not found' });
    const { title, author, genre, emoji, description } = req.body;
    let { cover_url, cover_public_id, pdf_url, pdf_public_id, pdf_name } = existing;
    if (req.files?.cover?.[0]) {
      await deleteFile(existing.cover_public_id, existing.cover_url);
      const c = await storeFile(req.files.cover[0], 'image');
      cover_url = c.url; cover_public_id = c.public_id;
    }
    if (req.files?.pdf?.[0]) {
      await deleteFile(existing.pdf_public_id, existing.pdf_url, 'raw');
      const p = await storeFile(req.files.pdf[0], 'pdf');
      pdf_url = p.url; pdf_public_id = p.public_id;
      pdf_name = req.files.pdf[0].originalname?.slice(0,200);
    }
    db.prepare(`UPDATE books SET title=?,author=?,genre=?,emoji=?,description=?,cover_url=?,cover_public_id=?,pdf_name=?,pdf_url=?,pdf_public_id=? WHERE id=?`)
      .run(title?.slice(0,200), author?.slice(0,200), genre?.slice(0,50),
        (emoji||'📖').slice(0,10), (description||'').slice(0,1000),
        cover_url, cover_public_id, pdf_name, pdf_url, pdf_public_id, req.params.id);
    res.json(db.prepare('SELECT * FROM books WHERE id=?').get(req.params.id));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/books/:id', requireAdmin, async (req, res) => {
  try {
    const book = db.prepare('SELECT * FROM books WHERE id=?').get(req.params.id);
    if (!book) return res.status(404).json({ error: 'Not found' });
    await deleteFile(book.cover_public_id, book.cover_url);
    await deleteFile(book.pdf_public_id, book.pdf_url, 'raw');
    db.prepare('DELETE FROM books WHERE id=?').run(req.params.id);
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: 'Server error' }); }
});

// ── AUTHORS ────────────────────────────────────────────────────────────────
app.get('/api/authors', (req, res) => {
  try { res.json(db.prepare('SELECT * FROM authors ORDER BY name ASC').all()); }
  catch(e) { res.status(500).json({ error: 'Server error' }); }
});

app.get('/api/authors/:id', (req, res) => {
  try {
    const a = db.prepare('SELECT * FROM authors WHERE id=?').get(req.params.id);
    if (!a) return res.status(404).json({ error: 'Not found' });
    const books = db.prepare('SELECT * FROM books WHERE lower(author)=lower(?) ORDER BY created_at DESC').all(a.name);
    res.json({ ...a, books });
  } catch(e) { res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/authors', requireAdmin, uploadLimiter, memUpload.single('photo'), async (req, res) => {
  try {
    const { name, bio, website } = req.body;
    if (!name) return res.status(400).json({ error: 'Name is required' });
    const photo = await storeFile(req.file, 'image');
    const result = db.prepare(`INSERT INTO authors (name,bio,photo_url,photo_public_id,website) VALUES (?,?,?,?,?)`)
      .run(name.trim().slice(0,200), (bio||'').slice(0,2000), photo.url, photo.public_id, (website||'').slice(0,500));
    res.json(db.prepare('SELECT * FROM authors WHERE id=?').get(result.lastInsertRowid));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/authors/:id', requireAdmin, uploadLimiter, memUpload.single('photo'), async (req, res) => {
  try {
    const existing = db.prepare('SELECT * FROM authors WHERE id=?').get(req.params.id);
    if (!existing) return res.status(404).json({ error: 'Not found' });
    const { name, bio, website } = req.body;
    let { photo_url, photo_public_id } = existing;
    if (req.file) {
      await deleteFile(existing.photo_public_id, existing.photo_url);
      const p = await storeFile(req.file, 'image');
      photo_url = p.url; photo_public_id = p.public_id;
    }
    db.prepare(`UPDATE authors SET name=?,bio=?,photo_url=?,photo_public_id=?,website=? WHERE id=?`)
      .run(name?.slice(0,200), (bio||'').slice(0,2000), photo_url, photo_public_id, (website||'').slice(0,500), req.params.id);
    res.json(db.prepare('SELECT * FROM authors WHERE id=?').get(req.params.id));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/authors/:id', requireAdmin, async (req, res) => {
  try {
    const a = db.prepare('SELECT * FROM authors WHERE id=?').get(req.params.id);
    if (!a) return res.status(404).json({ error: 'Not found' });
    await deleteFile(a.photo_public_id, a.photo_url);
    db.prepare('DELETE FROM authors WHERE id=?').run(req.params.id);
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: 'Server error' }); }
});

// ── PDF PROXY ──────────────────────────────────────────────────────────────
app.get('/api/pdf/:id', (req, res) => {
  try {
    const book = db.prepare('SELECT * FROM books WHERE id=?').get(req.params.id);
    if (!book || !book.pdf_url) return res.status(404).json({ error: 'PDF not found' });
    let fetchUrl = book.pdf_url;
    if (cloudinaryReady && book.pdf_public_id) {
      fetchUrl = cloudinary.utils.private_download_url(book.pdf_public_id, 'pdf', {
        resource_type: 'raw',
        expires_at: Math.floor(Date.now()/1000) + 3600,
        attachment: false,
      });
    }
    const client = fetchUrl.startsWith('https') ? https : http;
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `inline; filename="${(book.pdf_name || book.title + '.pdf').replace(/[^a-zA-Z0-9.\-_ ]/g,'_')}"`);
    const request = client.get(fetchUrl, (stream) => {
      if (stream.statusCode >= 400) {
        console.error('PDF fetch failed:', stream.statusCode);
        res.status(stream.statusCode).send('Could not load PDF.');
        return;
      }
      stream.pipe(res);
    });
    request.on('error', (e) => res.status(500).send('Error fetching PDF.'));
  } catch(e) { res.status(500).json({ error: 'Server error' }); }
});

// ── START ──────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n📚 Maktaba running on port ${PORT}`);
  console.log(`👉 Local: http://localhost:${PORT}\n`);
  if (!process.env.SESSION_SECRET) console.warn('⚠️  Set SESSION_SECRET environment variable!');
  if (!process.env.ADMIN_PASSWORD) console.warn('⚠️  Set ADMIN_PASSWORD environment variable to change default password!');
});
