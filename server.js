require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs'); // استخدام bcryptjs
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());

// التحقق من متغيرات البيئة
if (!process.env.DATABASE_URL || !process.env.JWT_SECRET) {
    console.error('Missing required environment variables: DATABASE_URL or JWT_SECRET');
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
                password VARCHAR(255) NOT NULL,
                total_points INTEGER DEFAULT 0,
                current_level INTEGER DEFAULT 1,
                stats JSONB DEFAULT '{"strength": 0, "stamina": 0, "intelligence": 0, "agility": 0, "general": 0}'
            );
        `);
        await pool.query(`
            CREATE TABLE IF NOT EXISTS tasks (
                id VARCHAR(255) PRIMARY KEY,
                user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                title VARCHAR(255) NOT NULL,
                description TEXT,
                difficulty VARCHAR(50) NOT NULL,
                difficulty_text VARCHAR(50) NOT NULL,
                category VARCHAR(50) NOT NULL,
                category_text VARCHAR(50) NOT NULL,
                category_icon_class VARCHAR(50) NOT NULL,
                points INTEGER NOT NULL,
                completed BOOLEAN DEFAULT FALSE
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

// Middleware للتحقق من التوكن
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) {
        console.error('No token provided');
        return res.status(401).json({ error: 'التوكن غير موجود' });
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) {
            console.error('Invalid or expired token:', err.message);
            return res.status(403).json({ error: 'التوكن غير صالح أو منتهي الصلاحية' });
        }
        req.user = user;
        next();
    });
};

// نقطة نهاية لإنشاء حساب
app.post('/api/auth/signup', async (req, res) => {
    const { email, password } = req.body;
    console.log('Signup attempt for:', email);

    if (!email || !password) {
        console.error('Missing email or password');
        return res.status(400).json({ error: 'البريد الإلكتروني وكلمة المرور مطلوبان' });
    }

    if (password.length < 6) {
        console.error('Password too short for:', email);
        return res.status(400).json({ error: 'كلمة المرور يجب أن تكون 6 أحرف على الأقل' });
    }

    try {
        console.log('Hashing password for:', email);
        const hashedPassword = await bcrypt.hash(password, 10);
        console.log('Password hashed successfully for:', email);

        console.log('Inserting user into database:', email);
        const result = await pool.query(
            'INSERT INTO users (email, password) VALUES ($1, $2) RETURNING id',
            [email, hashedPassword]
        );
        const userId = result.rows[0].id;
        console.log('User inserted successfully, ID:', userId);

        console.log('Generating JWT for user:', userId);
        const token = jwt.sign({ id: userId }, process.env.JWT_SECRET, { expiresIn: '1d' });
        console.log('JWT generated successfully for:', email);

        res.status(201).json({ token, userId });
    } catch (error) {
        console.error('Signup error:', error.message, error.stack);
        if (error.code === '23505') {
            console.error('Email already exists:', email);
            return res.status(400).json({ error: 'البريد الإلكتروني مستخدم بالفعل' });
        }
        res.status(500).json({ error: 'خطأ في الخادم، حاول لاحقًا' });
    }
});

// نقطة نهاية لتسجيل الدخول
app.post('/api/auth/signin', async (req, res) => {
    const { email, password } = req.body;
    console.log('Signin attempt for:', email);

    if (!email || !password) {
        console.error('Missing email or password');
        return res.status(400).json({ error: 'البريد الإلكتروني وكلمة المرور مطلوبان' });
    }

    try {
        const result = await pool.query('SELECT id, password FROM users WHERE email = $1', [email]);
        if (result.rows.length === 0) {
            console.error('User not found:', email);
            return res.status(401).json({ error: 'البريد الإلكتروني أو كلمة المرور غير صحيحة' });
        }

        const user = result.rows[0];
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            console.error('Invalid password for:', email);
            return res.status(401).json({ error: 'البريد الإلكتروني أو كلمة المرور غير صحيحة' });
        }

        const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: '1d' });
        console.log('User signed in successfully:', email);
        res.json({ token, userId: user.id });
    } catch (error) {
        console.error('Signin error:', error.message, error.stack);
        res.status(500).json({ error: 'خطأ في الخادم، حاول لاحقًا' });
    }
});

// نقطة نهاية للتحقق من المستخدم
app.get('/api/auth/me', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query('SELECT id, email FROM users WHERE id = $1', [req.user.id]);
        if (result.rows.length === 0) {
            console.error('User not found:', req.user.id);
            return res.status(404).json({ error: 'المستخدم غير موجود' });
        }
        console.log('User verified:', req.user.id);
        res.json({ userId: result.rows[0].id });
    } catch (error) {
        console.error('Error fetching user:', error.message, error.stack);
        res.status(500).json({ error: 'خطأ في الخادم، حاول لاحقًا' });
    }
});

// نقطة نهاية لإضافة مهمة
app.post('/api/tasks', authenticateToken, async (req, res) => {
    const { id, title, description, difficulty, difficulty_text, category, category_text, category_icon_class, points, completed } = req.body;
    console.log('Adding task for user:', req.user.id);

    if (!id || !title || !difficulty || !difficulty_text || !category || !category_text || !category_icon_class || !points) {
        console.error('Missing required task fields');
        return res.status(400).json({ error: 'جميع الحقول المطلوبة يجب أن تكون موجودة' });
    }

    try {
        await pool.query(
            'INSERT INTO tasks (id, user_id, title, description, difficulty, difficulty_text, category, category_text, category_icon_class, points, completed) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)',
            [id, req.user.id, title, description, difficulty, difficulty_text, category, category_text, category_icon_class, points, completed]
        );
        console.log('Task added successfully for user:', req.user.id);
        res.status(201).json({ message: 'تم إضافة المهمة بنجاح' });
    } catch (error) {
        console.error('Error adding task:', error.message, error.stack);
        res.status(500).json({ error: 'خطأ في الخادم، حاول لاحقًا' });
    }
});

// نقطة نهاية لجلب المهام
app.get('/api/tasks', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM tasks WHERE user_id = $1', [req.user.id]);
        console.log('Tasks fetched for user:', req.user.id);
        res.json(result.rows);
    } catch (error) {
        console.error('Error fetching tasks:', error.message, error.stack);
        res.status(500).json({ error: 'خطأ في الخادم، حاول لاحقًا' });
    }
});

// نقطة نهاية لإتمام مهمة
app.patch('/api/tasks/:id/complete', authenticateToken, async (req, res) => {
    const taskId = req.params.id;
    console.log('Completing task:', taskId, 'for user:', req.user.id);

    try {
        const taskResult = await pool.query('SELECT * FROM tasks WHERE id = $1 AND user_id = $2', [taskId, req.user.id]);
        if (taskResult.rows.length === 0) {
            console.error('Task not found or unauthorized:', taskId);
            return res.status(404).json({ error: 'المهمة غير موجودة أو لا تملك الصلاحية' });
        }

        const task = taskResult.rows[0];
        if (task.completed) {
            console.error('Task already completed:', taskId);
            return res.status(400).json({ error: 'المهمة مكتملة بالفعل' });
        }

        await pool.query('UPDATE tasks SET completed = TRUE WHERE id = $1', [taskId]);
        const points = task.points;
        const category = task.category;

        const userResult = await pool.query('SELECT total_points, stats FROM users WHERE id = $1', [req.user.id]);
        const user = userResult.rows[0];
        const newTotalPoints = user.total_points + points;
        const newStats = { ...user.stats, [category]: (user.stats[category] || 0) + points };

        const levelThresholds = [0, 100, 300, 600, 1000, 1500, 2100, 3000, 4000, 5500];
        let newLevel = user.current_level;
        for (let i = levelThresholds.length - 1; i >= 0; i--) {
            if (newTotalPoints >= levelThresholds[i]) {
                newLevel = i + 1;
                break;
            }
        }

        await pool.query(
            'UPDATE users SET total_points = $1, current_level = $2, stats = $3 WHERE id = $4',
            [newTotalPoints, newLevel, newStats, req.user.id]
        );
        console.log('Task completed successfully:', taskId);
        res.json({ message: 'تم إتمام المهمة بنجاح' });
    } catch (error) {
        console.error('Error completing task:', error.message, error.stack);
        res.status(500).json({ error: 'خطأ في الخادم، حاول لاحقًا' });
    }
});

// نقطة نهاية لحذف مهمة
app.delete('/api/tasks/:id', authenticateToken, async (req, res) => {
    const taskId = req.params.id;
    console.log('Deleting task:', taskId, 'for user:', req.user.id);

    try {
        const result = await pool.query('DELETE FROM tasks WHERE id = $1 AND user_id = $2', [taskId, req.user.id]);
        if (result.rowCount === 0) {
            console.error('Task not found or unauthorized:', taskId);
            return res.status(404).json({ error: 'المهمة غير موجودة أو لا تملك الصلاحية' });
        }
        console.log('Task deleted successfully:', taskId);
        res.json({ message: 'تم حذف المهمة بنجاح' });
    } catch (error) {
        console.error('Error deleting task:', error.message, error.stack);
        res.status(500).json({ error: 'خطأ في الخادم، حاول لاحقًا' });
    }
});

// نقطة نهاية لجلب الإحصائيات
app.get('/api/stats', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query('SELECT total_points, current_level, stats FROM users WHERE id = $1', [req.user.id]);
        if (result.rows.length === 0) {
            console.error('User not found:', req.user.id);
            return res.status(404).json({ error: 'المستخدم غير موجود' });
        }
        const { total_points, current_level, stats } = result.rows[0];
        console.log('Stats fetched for user:', req.user.id);
        res.json({ totalPoints: total_points, currentLevel: current_level, stats });
    } catch (error) {
        console.error('Error fetching stats:', error.message, error.stack);
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
