const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const DATA_DIR = process.env.DATA_DIR || __dirname;
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
const DB_FILE = path.join(DATA_DIR, 'database.json');

app.use(cors());
app.use(express.json({ limit: '5mb' }));

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
  paymentSettings: {
    cardType: 'MasterCard',
    cardNumber: '',
    cardHolder: ''
  },
  customers: [],
  products: [
    {
      id: 'prod_1',
      name: 'ChatGPT Plus',
      duration: 'شهر واحد',
      price: 14.50,
      image: 'https://upload.wikimedia.org/wikipedia/commons/0/04/ChatGPT_logo.svg',
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
      image: 'https://cdn.jsdelivr.net/npm/simple-icons@13/icons/canva.svg',
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
      image: 'https://upload.wikimedia.org/wikipedia/commons/1/1c/Capcut-icon.svg',
      defaultNote: 'تسجيل دخول مباشر عبر البريد وكلمة المرور',
      stock: [
        { account: 'cap01@alphadigital.iq:Cap@7741', note: 'جهازين كحد أقصى' }
      ]
    }
  ],
  orders: [],
  settlements: []
};

function readDB() {
  try {
    if (!fs.existsSync(DB_FILE)) {
      fs.writeFileSync(DB_FILE, JSON.stringify(defaultDB, null, 2), 'utf8');
      return JSON.parse(JSON.stringify(defaultDB));
    }
    const data = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
    if (!Array.isArray(data.settlements)) data.settlements = [];
    if (!data.paymentSettings) data.paymentSettings = { cardType: 'MasterCard', cardNumber: '', cardHolder: '' };
    if (!Array.isArray(data.customers)) data.customers = [];
    (data.products || []).forEach(p => { if (typeof p.image !== 'string') p.image = ''; });
    if (data.apiSettings) delete data.apiSettings;
    (data.orders || []).forEach(o => {
      if (!o.status) o.status = (o.items && o.items.length) ? 'confirmed' : 'pending_payment';
      if (typeof o.buyer !== 'string') o.buyer = '';
    });
    (data.orders || []).forEach(o => { if (typeof o.settled !== 'boolean') o.settled = false; });
    return data;
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

// --- AUTH ROUTES ---
app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body || {};
  const db = readDB();
  const cleanUser = String(username || '').trim().toLowerCase();
  const cleanPass = String(password || '').trim();

  const found = Object.values(db.users).find(
    u => u.username.toLowerCase() === cleanUser && u.password === cleanPass
  );

  if (found) {
    const token = createSession(found);
    return res.json({
      success: true,
      token,
      user: { username: found.username, role: found.role }
    });
  }

  const customer = (db.customers || []).find(c => c.username === cleanUser);
  if (customer && customer.passwordHash === hashPassword(cleanPass, customer.salt)) {
    const token = createSession({ username: customer.username, role: 'customer' });
    return res.json({
      success: true,
      token,
      user: { username: customer.username, role: 'customer' }
    });
  }

  return res.status(401).json({ success: false, error: 'اسم المستخدم أو كلمة المرور غير صحيحة' });
});

function hashPassword(password, salt) {
  return crypto.createHash('sha256').update(salt + ':' + password).digest('hex');
}

// --- CUSTOMER REGISTRATION ---
app.post('/api/auth/register', (req, res) => {
  const { username, password } = req.body || {};
  const cleanUser = String(username || '').trim().toLowerCase();
  const cleanPass = String(password || '').trim();

  if (!/^[a-z0-9_.]{3,20}$/.test(cleanUser)) {
    return res.status(400).json({ success: false, error: 'اسم المستخدم يجب أن يكون 3-20 حرفاً (أحرف إنجليزية وأرقام ونقطة و _)' });
  }
  if (cleanPass.length < 4) {
    return res.status(400).json({ success: false, error: 'كلمة المرور قصيرة — 4 أحرف على الأقل' });
  }

  const db = readDB();
  const taken = Object.values(db.users).some(u => u.username.toLowerCase() === cleanUser)
    || (db.customers || []).some(c => c.username === cleanUser);
  if (taken) {
    return res.status(400).json({ success: false, error: 'اسم المستخدم محجوز، جرّب اسماً آخر' });
  }

  const salt = crypto.randomBytes(8).toString('hex');
  db.customers.push({
    username: cleanUser,
    passwordHash: hashPassword(cleanPass, salt),
    salt,
    createdAt: new Date().toISOString()
  });
  writeDB(db);

  const token = createSession({ username: cleanUser, role: 'customer' });
  res.json({ success: true, token, user: { username: cleanUser, role: 'customer' } });
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
    image: p.image || '',
    stockCount: p.stock.length,
    stock: isAdmin ? p.stock : undefined
  }));

  let orders = db.orders;
  if (!isAdmin) {
    orders = db.orders.filter(o => o.buyer === req.user.username || (req.user.role === 'user' && !o.buyer));
  }
  const safeOrders = orders.map(o => ({
    ...o,
    receiptImage: (isAdmin || o.buyer === req.user.username) ? o.receiptImage : undefined,
    // Reserved accounts stay hidden from the buyer until the admin confirms payment
    items: (isAdmin || o.status === 'confirmed') ? (o.items || []) : []
  }));

  res.json({
    success: true,
    products,
    orders: safeOrders,
    settlements: db.settlements || [],
    paymentSettings: db.paymentSettings || { cardType: 'MasterCard', cardNumber: '', cardHolder: '' },
    customers: isAdmin ? (db.customers || []).map(c => ({ username: c.username, createdAt: c.createdAt })) : undefined
  });
});

// Buy Order with payment receipt (Customer via Web Portal)
// Buyer transfers to the MasterCard and uploads a transfer screenshot;
// stock is pulled only after the admin confirms the payment.
app.post('/api/portal/orders', authMiddleware(), (req, res) => {
  if (req.user.role === 'admin') {
    return res.status(403).json({ success: false, error: 'حساب الإدارة لا يمكنه الشراء' });
  }
  const { productId, quantity, receiptImage } = req.body || {};
  const qty = parseInt(quantity, 10) || 1;
  if (qty < 1) return res.status(400).json({ success: false, error: 'الكمية غير صحيحة' });
  if (!receiptImage || typeof receiptImage !== 'string' || !receiptImage.startsWith('data:image/')) {
    return res.status(400).json({ success: false, error: 'يرجى رفع صورة إثبات التحويل' });
  }
  if (receiptImage.length > 5 * 1024 * 1024) {
    return res.status(400).json({ success: false, error: 'صورة الإثبات كبيرة جداً' });
  }

  const db = readDB();
  const product = db.products.find(p => p.id === productId);
  if (!product) return res.status(404).json({ success: false, error: 'المنتج غير موجود' });
  if (product.stock.length < qty) {
    return res.status(400).json({ success: false, error: 'المخزون المتوفر غير كافٍ' });
  }

  // Reserve the accounts immediately so two buyers can never pay for the same stock.
  // They leave available stock now and are returned automatically if the order is rejected.
  const reservedItems = product.stock.splice(0, qty);
  let orderId = '';
  do {
    orderId = 'ORD-' + Math.floor(100000 + Math.random() * 900000);
  } while (db.orders.some(o => o.id === orderId));

  const order = {
    id: orderId,
    productId: product.id,
    productName: product.name,
    duration: product.duration,
    quantity: qty,
    unitPrice: product.price,
    totalPrice: Number((product.price * qty).toFixed(2)),
    source: 'WEB',
    buyer: req.user.username,
    status: 'pending_payment',
    receiptImage,
    settled: false,
    items: reservedItems,
    createdAt: new Date().toISOString()
  };

  db.orders.unshift(order);
  writeDB(db);
  res.json({ success: true, order: { ...order, receiptImage: undefined, items: [] } });
});

// Admin: Create or Update Product
app.post('/api/admin/products', authMiddleware('admin'), (req, res) => {
  const { id, name, duration, price, defaultNote, image } = req.body || {};
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
    existing.image = String(image || '').trim();
  } else {
    db.products.push({
      id: 'prod_' + Date.now(),
      name: String(name).trim(),
      duration: String(duration).trim(),
      price: Number(parseFloat(price).toFixed(2)),
      defaultNote: String(defaultNote || '').trim(),
      image: String(image || '').trim(),
      stock: []
    });
  }

  writeDB(db);
  res.json({ success: true });
});

// Admin: Delete Product
app.delete('/api/admin/products/:id', authMiddleware('admin'), (req, res) => {
  const db = readDB();
  const hasPending = db.orders.some(o => o.productId === req.params.id && o.status === 'pending_payment');
  if (hasPending) {
    return res.status(400).json({ success: false, error: 'لا يمكن حذف المنتج — توجد طلبات معلقة بانتظار تأكيد الدفع' });
  }
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

// Admin: Update MasterCard Payment Settings & Admin Password
app.post('/api/admin/settings', authMiddleware('admin'), (req, res) => {
  const { adminPassword, paymentSettings } = req.body || {};
  const db = readDB();

  if (adminPassword && String(adminPassword).trim().length >= 3) {
    db.users.admin.password = String(adminPassword).trim();
  }
  if (paymentSettings && typeof paymentSettings === 'object') {
    db.paymentSettings = {
      cardType: 'MasterCard',
      cardNumber: String(paymentSettings.cardNumber || '').trim(),
      cardHolder: String(paymentSettings.cardHolder || '').trim()
    };
  }

  writeDB(db);
  res.json({ success: true, paymentSettings: db.paymentSettings });
});

// Admin: Settle all outstanding debt (mark every unsettled order settled)
app.post('/api/admin/settle', authMiddleware('admin'), (req, res) => {
  const db = readDB();
  const unsettled = db.orders.filter(o => !o.settled);
  if (!unsettled.length) {
    return res.json({ success: true, settledCount: 0, amount: 0, message: 'لا توجد ديون مستحقة' });
  }
  const amount = Number(unsettled.reduce((sum, o) => sum + (o.totalPrice || 0), 0).toFixed(2));
  const now = new Date().toISOString();
  unsettled.forEach(o => { o.settled = true; o.settledAt = now; });
  const settlement = {
    id: 'STL-' + Math.floor(100000 + Math.random() * 900000),
    amount,
    ordersCount: unsettled.length,
    orderIds: unsettled.map(o => o.id),
    settledAt: now,
    settledBy: req.user.username
  };
  db.settlements.unshift(settlement);
  writeDB(db);
  res.json({ success: true, settledCount: unsettled.length, amount, settlement });
});

// Admin: Confirm payment -> pull stock and deliver accounts to the buyer
app.post('/api/admin/orders/:id/confirm', authMiddleware('admin'), (req, res) => {
  const db = readDB();
  const order = db.orders.find(o => o.id === req.params.id);
  if (!order) return res.status(404).json({ success: false, error: 'الطلب غير موجود' });
  if (order.status !== 'pending_payment') {
    return res.status(400).json({ success: false, error: 'هذا الطلب ليس بانتظار التأكيد' });
  }
  const product = db.products.find(p => p.id === order.productId);
  if (!product) {
    return res.status(400).json({ success: false, error: 'المنتج غير موجود' });
  }
  // The accounts were already reserved for this order when it was created
  order.status = 'confirmed';
  order.settled = true;
  order.settledAt = new Date().toISOString();
  order.confirmedBy = req.user.username;
  writeDB(db);
  res.json({ success: true, order });
});

// Admin: Reject payment (no stock is touched)
app.post('/api/admin/orders/:id/reject', authMiddleware('admin'), (req, res) => {
  const db = readDB();
  const order = db.orders.find(o => o.id === req.params.id);
  if (!order) return res.status(404).json({ success: false, error: 'الطلب غير موجود' });
  if (order.status !== 'pending_payment') {
    return res.status(400).json({ success: false, error: 'هذا الطلب ليس بانتظار التأكيد' });
  }
  // Return the reserved accounts to available stock
  const product = db.products.find(p => p.id === order.productId);
  if (product && order.items && order.items.length) {
    product.stock.push(...order.items);
  }
  order.status = 'rejected';
  writeDB(db);
  res.json({ success: true });
});

app.listen(PORT, () => {
  console.log(`Alpha Digital Portal running on port ${PORT}`);
  console.log('Database file:', DB_FILE);
});
