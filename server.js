const express = require('express');
const { neon } = require('@neondatabase/serverless');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();

// إعدادات Middleware
app.use(cors());
app.use(express.json());

// الاتصال بقاعدة بيانات Neon
const sql = neon(process.env.DATABASE_URL);

// مفتاح سري لـ JWT (يجب تخزينه في متغيرات البيئة في Vercel)
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

// إنشاء جدول المستخدمين إذا لم يكن موجودًا
async function initializeDatabase() {
  try {
    await sql`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `;
    console.log('Database initialized');
  } catch (error) {
    console.error('Error initializing database:', error);
  }
}

initializeDatabase();

// مسار إنشاء حساب
app.post('/api/auth/signup', async (req, res) => {
  const { email, password } = req.body;

  try {
    // التحقق من وجود المستخدم
    const existingUser = await sql`SELECT * FROM users WHERE email = ${email}`;
    if (existingUser.length > 0) {
      return res.status(400).json({ error: 'البريد الإلكتروني مستخدم بالفعل' });
    }

    // تشفير كلمة المرور
    const hashedPassword = await bcrypt.hash(password, 10);

    // إضافة المستخدم إلى قاعدة البيانات
    const [newUser] = await sql`
      INSERT INTO users (email, password)
      VALUES (${email}, ${hashedPassword})
      RETURNING id, email
    `;

    // إنشاء توكن JWT
    const token = jwt.sign({ userId: newUser.id, email: newUser.email }, JWT_SECRET, {
      expiresIn: '1h',
    });

    res.status(201).json({ token, userId: newUser.id });
  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ error: 'خطأ أثناء إنشاء الحساب' });
  }
});

// تصدير التطبيق ليعمل كـ serverless function على Vercel
module.exports = app;
