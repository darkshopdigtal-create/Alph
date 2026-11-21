const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const DB_FILE = path.join(__dirname, 'database.json');

app.use(cors());
app.use(express.json());

// Serve index.html directly from the root directory
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// Default Initial Database
const defaultDB = {
  users: {
    admin: { username: 'admin', password: process.env.ADMIN_PASSWORD || '1234', role: 'admin' },
    user: { username: 'user', password: process.env.USER_PASSWORD || '1234', role: 'user' }
  },
  apiSettings: {
    enabled: true,
    apiKey: 'ad_live_' + crypto.randomBytes(16).toString('hex')
  },
  products: [
    {
      id: 'prod_1',
      name: 'ChatGPT Plus',
      duration: 'شهر واحد',
      price: 14.50,
      defaultNote: 'حساب خاص - لا تقم بتغيير البريد الإلكتروني',
      stock: [
        { account: 'gpt01@alphadigital.iq:Pass#9921', note: 'حساب خاص - ضمان 28 يوم' },
        { account: 'gpt02@alphadigital.iq:Pass#8842', note: 'حساب خاص - ضمان 28 يوم' }
      ]
    },
    {
      id: 'prod_2',
      name: 'Canva Pro',
      duration: 'سنة كاملة',
      price: 4.00,
      defaultNote: 'دعوة فريق رسمية على إيميل العميل',
      stock: [
        { account: 'https://canva.com/brand/join?token=AD9912X', note: 'رابط دعوة مباشر' }
      ]
    },
    {
      id: 'prod_3',
      name: 'CapCut Pro',
      duration: 'شهر واحد',
      price: 5.50,
      defaultNote: 'تسجيل دخول مباشر عبر البريد وكلمة المرور',
      stock: [
        { account: 'cap01@alphadigital.iq:Cap@7741', note: 'جهازين كحد أقصى' }
      ]
    }
  ],
  orders: []
};

function readDB() {
  try {
    if (!fs.existsSync(DB_FILE)) {
      fs.writeFileSync(DB_FILE, JSON.stringify(defaultDB, null, 2), 'utf8');
      return JSON.parse(JSON.stringify(defaultDB));
    }
    return JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
  } catch (err) {
    return JSON.parse(JSON.stringify(defaultDB));
  }
}

function writeDB(data) {
  fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2), 'utf8');
}

// Initialize DB on startup
readDB();

// Simple Token Store in Memory
const activeSessions = new Map();

function createSession(user) {
  const token = crypto.randomBytes(24).toString('hex');
  activeSessions.set(token, { username: user.username, role: user.role, createdAt: Date.now() });
  return token;
}

function authMiddleware(requiredRole) {
  return (req, res, next) => {
    const authHeader = req.headers['authorization'] || '';
    const token = authHeader.replace('Bearer ', '').trim();
    const session = activeSessions.get(token);
    if (!session) {
      return res.status(401).json({ success: false, error: 'غير مصرح بالدخول، يرجى تسجيل الدخول مجدداً' });
    }
    if (requiredRole && session.role !== requiredRole) {
      return res.status(403).json({ success: false, error: 'صلاحيات غير كافية' });
    }
    req.user = session;
    next();
  };
}

function apiKeyMiddleware(req, res, next) {
  const db = readDB();
  if (!db.apiSettings.enabled) {
    return res.status(403).json({ success: false, error: 'تم إيقاف خدمة API من قبل الإدارة' });
  }
  const key = req.headers['x-api-key'] || req.query.api_key;
  if (!key || key !== db.apiSettings.apiKey) {
    return res.status(401).json({ success: false, error: 'مفتاح API غير صالح' });
  }
  next();
}

// --- AUTH ROUTES ---
app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body || {};
  const db = readDB();
  const cleanUser = String(username || '').trim().toLowerCase();
  const cleanPass = String(password || '').trim();

  const found = Object.values(db.users).find(
    u => u.username.toLowerCase() === cleanUser && u.password === cleanPass
  );

  if (!found) {
    return res.status(401).json({ success: false, error: 'اسم المستخدم أو كلمة المرور غير صحيحة' });
  }

  const token = createSession(found);
  res.json({
    success: true,
    token,
    user: { username: found.username, role: found.role }
  });
});

app.get('/api/auth/me', authMiddleware(), (req, res) => {
  res.json({ success: true, user: req.user });
});

// --- INTERNAL PORTAL ROUTES ---
app.get('/api/portal/state', authMiddleware(), (req, res) => {
  const db = readDB();
  const isAdmin = req.user.role === 'admin';

  const products = db.products.map(p => ({
    id: p.id,
    name: p.name,
    duration: p.duration,
    price: p.price,
    defaultNote: p.defaultNote || '',
    stockCount: p.stock.length,
    stock: isAdmin ? p.stock : undefined
  }));

  res.json({
    success: true,
    products,
    orders: db.orders,
    apiSettings: db.apiSettings,
    users: isAdmin ? {
      adminUsername: db.users.admin.username,
      userUsername: db.users.user.username
    } : undefined
  });
});

// Pull Order (User via Web Portal)
app.post('/api/portal/orders', authMiddleware(), (req, res) => {
  const { productId, quantity } = req.body || {};
  const qty = parseInt(quantity, 10) || 1;
  if (qty < 1) return res.status(400).json({ success: false, error: 'الكمية غير صحيحة' });

  const db = readDB();
  const product = db.products.find(p => p.id === productId);
  if (!product) return res.status(404).json({ success: false, error: 'المنتج غير موجود' });
  if (product.stock.length < qty) {
    return res.status(400).json({ success: false, error: 'المخزون المتوفر غير كافٍ' });
  }

  const pulledItems = product.stock.splice(0, qty);
  const order = {
    id: 'ORD-' + Math.floor(100000 + Math.random() * 900000),
    productId: product.id,
    productName: product.name,
    duration: product.duration,
    quantity: qty,
    unitPrice: product.price,
    totalPrice: Number((product.price * qty).toFixed(2)),
    source: 'WEB',
    items: pulledItems,
    createdAt: new Date().toISOString()
  };

  db.orders.unshift(order);
  writeDB(db);
  res.json({ success: true, order });
});

// Admin: Create or Update Product
app.post('/api/admin/products', authMiddleware('admin'), (req, res) => {
  const { id, name, duration, price, defaultNote } = req.body || {};
  if (!name || !duration || isNaN(parseFloat(price))) {
    return res.status(400).json({ success: false, error: 'يرجى إكمال بيانات المنتج بشكل صحيح' });
  }

  const db = readDB();
  if (id) {
    const existing = db.products.find(p => p.id === id);
    if (!existing) return res.status(404).json({ success: false, error: 'المنتج غير موجود' });
    existing.name = String(name).trim();
    existing.duration = String(duration).trim();
    existing.price = Number(parseFloat(price).toFixed(2));
    existing.defaultNote = String(defaultNote || '').trim();
  } else {
    db.products.push({
      id: 'prod_' + Date.now(),
      name: String(name).trim(),
      duration: String(duration).trim(),
      price: Number(parseFloat(price).toFixed(2)),
      defaultNote: String(defaultNote || '').trim(),
      stock: []
    });
  }

  writeDB(db);
  res.json({ success: true });
});

// Admin: Delete Product
app.delete('/api/admin/products/:id', authMiddleware('admin'), (req, res) => {
  const db = readDB();
  db.products = db.products.filter(p => p.id !== req.params.id);
  writeDB(db);
  res.json({ success: true });
});

// Admin: Add Stock with Note
app.post('/api/admin/products/:id/stock', authMiddleware('admin'), (req, res) => {
  const { accountsText, note } = req.body || {};
  const lines = String(accountsText || '')
    .split(/\r?\n/)
    .map(l => l.trim())
    .filter(Boolean);

  if (!lines.length) {
    return res.status(400).json({ success: false, error: 'يرجى إدخال حساب واحد على الأقل' });
  }

  const db = readDB();
  const product = db.products.find(p => p.id === req.params.id);
  if (!product) return res.status(404).json({ success: false, error: 'المنتج غير موجود' });

  const appliedNote = String(note || '').trim() || product.defaultNote || '';
  lines.forEach(acc => {
    product.stock.push({ account: acc, note: appliedNote });
  });

  writeDB(db);
  res.json({ success: true, added: lines.length });
});

// Admin: Remove single stock item
app.delete('/api/admin/products/:id/stock/:index', authMiddleware('admin'), (req, res) => {
  const idx = parseInt(req.params.index, 10);
  const db = readDB();
  const product = db.products.find(p => p.id === req.params.id);
  if (!product || isNaN(idx) || idx < 0 || idx >= product.stock.length) {
    return res.status(400).json({ success: false, error: 'عنصر غير صالح' });
  }
  product.stock.splice(idx, 1);
  writeDB(db);
  res.json({ success: true });
});

// Admin: Update API Settings & Passwords
app.post('/api/admin/settings', authMiddleware('admin'), (req, res) => {
  const { enabled, regenerateKey, adminPassword, userPassword } = req.body || {};
  const db = readDB();

  if (typeof enabled === 'boolean') {
    db.apiSettings.enabled = enabled;
  }
  if (regenerateKey) {
    db.apiSettings.apiKey = 'ad_live_' + crypto.randomBytes(16).toString('hex');
  }
  if (adminPassword && String(adminPassword).trim().length >= 3) {
    db.users.admin.password = String(adminPassword).trim();
  }
  if (userPassword && String(userPassword).trim().length >= 3) {
    db.users.user.password = String(userPassword).trim();
  }

  writeDB(db);
  res.json({ success: true, apiSettings: db.apiSettings });
});

// --- PUBLIC EXTERNAL REST API (FOR RESELLER INTEGRATION) ---
app.get('/api/v1/products', apiKeyMiddleware, (req, res) => {
  const db = readDB();
  const list = db.products.map(p => ({
    id: p.id,
    name: p.name,
    duration: p.duration,
    price: p.price,
    available_stock: p.stock.length
  }));
  res.json({ success: true, products: list });
});

app.post('/api/v1/orders', apiKeyMiddleware, (req, res) => {
  const { product_id, quantity } = req.body || {};
  const qty = parseInt(quantity, 10) || 1;
  if (!product_id || qty < 1) {
    return res.status(400).json({ success: false, error: 'Invalid product_id or quantity' });
  }

  const db = readDB();
  const product = db.products.find(p => p.id === product_id);
  if (!product) {
    return res.status(404).json({ success: false, error: 'Product not found' });
  }
  if (product.stock.length < qty) {
    return res.status(400).json({ success: false, error: 'Insufficient stock', available: product.stock.length });
  }

  const pulledItems = product.stock.splice(0, qty);
  const order = {
    id: 'ORD-' + Math.floor(100000 + Math.random() * 900000),
    productId: product.id,
    productName: product.name,
    duration: product.duration,
    quantity: qty,
    unitPrice: product.price,
    totalPrice: Number((product.price * qty).toFixed(2)),
    source: 'API',
    items: pulledItems,
    createdAt: new Date().toISOString()
  };

  db.orders.unshift(order);
  writeDB(db);

  res.json({
    success: true,
    order_id: order.id,
    product: order.productName,
    quantity: order.quantity,
    total_price: order.totalPrice,
    items: order.items,
    created_at: order.createdAt
  });
});

app.get('/api/v1/orders', apiKeyMiddleware, (req, res) => {
  const db = readDB();
  res.json({
    success: true,
    orders: db.orders.map(o => ({
      order_id: o.id,
      product: o.productName,
      quantity: o.quantity,
      total_price: o.totalPrice,
      source: o.source,
      items: o.items,
      created_at: o.createdAt
    }))
  });
});

app.listen(PORT, () => {
  console.log(`Alpha Digital Portal running on port ${PORT}`);
});
