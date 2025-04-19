require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());

// التحقق من متغيرات البيئة
if (!process.env.DATABASE_URL) {
    console.error('Missing required environment variable: DATABASE_URL');
    process.exit(1);
}

// Neon database connection
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

// اختبار الاتصال بقاعدة البيانات
pool.connect((err, client, release) => {
    if (err) {
        console.error('Error connecting to Neon database:', err.message, err.stack);
        process.exit(1);
    }
    console.log('Connected to Neon database successfully');
    release();
});

// تهيئة قاعدة البيانات
async function initializeDatabase() {
    try {
        console.log('Initializing database...');
        await pool.query(`
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                email VARCHAR(255) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL
            );
        `);
        console.log('Database initialized successfully');
    } catch (error) {
        console.error('Error initializing database:', error.message, error.stack);
        process.exit(1);
    }
}

// استدعاء التهيئة عند بدء التطبيق
initializeDatabase();

// نقطة نهاية لإنشاء حساب
app.post('/api/auth/signup', async (req, res) => {
    const { email, password } = req.body;
    console.log('Signup attempt for:', email);

    if (!email || !password) {
        console.error('Missing email or password');
        return res.status(400).json({ error: 'البريد الإلكتروني وكلمة المرور مطلوبان' });
    }

    try {
        console.log('Inserting user into database:', email);
        const result = await pool.query(
            'INSERT INTO users (email, password) VALUES ($1, $2) RETURNING id',
            [email, password]
        );
        const userId = result.rows[0].id;
        console.log('User inserted successfully, ID:', userId);

        res.status(201).json({ message: 'تم إنشاء الحساب بنجاح', userId });
    } catch (error) {
        console.error('Signup error:', error.message, error.stack);
        if (error.code === '23505') {
            console.error('Email already exists:', email);
            return res.status(400).json({ error: 'البريد الإلكتروني مستخدم بالفعل' });
        }
        res.status(500).json({ error: 'خطأ في الخادم، حاول لاحقًا' });
    }
});

// نقطة نهاية للتحقق من صحة التطبيق
app.get('/api/health', (req, res) => {
    console.log('Health check requested');
    res.status(200).json({ status: 'OK', message: 'Server is running' });
});

// تشغيل الخادم
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
