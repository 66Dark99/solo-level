const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());

// التحقق من متغيرات البيئة
if (!process.env.DATABASE_URL || !process.env.JWT_SECRET) {
    console.error('Missing required environment variables: DATABASE_URL and JWT_SECRET');
    process.exit(1);
}

// Neon database connection
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

// تهيئة قاعدة البيانات
async function initializeDatabase() {
    try {
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
        console.error('Error initializing database:', error);
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
        return res.status(401).json({ error: 'التوكن غير موجود' });
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'التوكن غير صالح أو منتهي الصلاحية' });
        }
        req.user = user;
        next();
    });
};

// نقطة نهاية للتحقق من المستخدم
app.get('/api/auth/me', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query('SELECT id, email FROM users WHERE id = $1', [req.user.id]);
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'المستخدم غير موجود' });
        }
        res.json({ userId: result.rows[0].id });
    } catch (error) {
        console.error('Error fetching user:', error);
        res.status(500).json({ error: 'خطأ في الخادم، حاول لاحقًا' });
    }
});

// مسارات المصادقة
app.post('/api/auth/signin', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.status(400).json({ error: 'البريد الإلكتروني وكلمة المرور مطلوبان' });
    }

    try {
        const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        const user = result.rows[0];
        if (!user) {
            return res.status(404).json({ error: 'المستخدم غير موجود' });
        }

        const match = await bcrypt.compare(password, user.password);
        if (!match) {
            return res.status(401).json({ error: 'كلمة المرور غير صحيحة' });
        }

        const token = jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '1h' });
        res.json({ token, userId: user.id });
    } catch (error) {
        console.error('Signin error:', error);
        res.status(500).json({ error: 'خطأ في الخادم، حاول لاحقًا' });
    }
});

app.post('/api/auth/signup', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.status(400).json({ error: 'البريد الإلكتروني وكلمة المرور مطلوبان' });
    }

    try {
        const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        if (result.rows.length > 0) {
            return res.status(400).json({ error: 'البريد الإلكتروني مسجل مسبقًا' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = await pool.query(
            'INSERT INTO users (email, password, total_points, current_level, stats) VALUES ($1, $2, $3, $4, $5) RETURNING id, email',
            [email, hashedPassword, 0, 1, { strength: 0, stamina: 0, intelligence: 0, agility: 0, general: 0 }]
        );

        const token = jwt.sign({ id: newUser.rows[0].id, email: newUser.rows[0].email }, process.env.JWT_SECRET, { expiresIn: '1h' });
        res.status(201).json({ token, userId: newUser.rows[0].id });
    } catch (error) {
        console.error('Signup error:', error);
        res.status(500).json({ error: 'خطأ في الخادم، حاول لاحقًا' });
    }
});

// مسارات المهام
app.get('/api/tasks', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM tasks WHERE user_id = $1', [req.user.id]);
        res.json(result.rows);
    } catch (error) {
        console.error('Error fetching tasks:', error);
        res.status(500).json({ error: 'خطأ في جلب المهام، حاول لاحقًا' });
    }
});

app.post('/api/tasks', authenticateToken, async (req, res) => {
    const taskData = req.body;
    if (!taskData.title || !taskData.difficulty || !taskData.category) {
        return res.status(400).json({ error: 'العنوان، مستوى الصعوبة، والفئة مطلوبة' });
    }

    try {
        await pool.query(
            'INSERT INTO tasks (id, user_id, title, description, difficulty, difficulty_text, category, category_text, category_icon_class, points, completed) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)',
            [
                taskData.id,
                req.user.id,
                taskData.title,
                taskData.description,
                taskData.difficulty,
                taskData.difficultyText,
                taskData.category,
                taskData.categoryText,
                taskData.categoryIconClass,
                taskData.points,
                taskData.completed
            ]
        );
        res.status(201).json({ message: 'تم إضافة المهمة بنجاح' });
    } catch (error) {
        console.error('Error creating task:', error);
        res.status(500).json({ error: 'خطأ في إضافة المهمة، حاول لاحقًا' });
    }
});

app.patch('/api/tasks/:id/complete', authenticateToken, async (req, res) => {
    const taskId = req.params.id;
    try {
        const result = await pool.query('UPDATE tasks SET completed = true WHERE id = $1 AND user_id = $2 RETURNING *', [taskId, req.user.id]);
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'المهمة غير موجودة أو ليست ملكك' });
        }

        const task = result.rows[0];
        await pool.query(
            'UPDATE users SET total_points = total_points + $1, stats = stats || jsonb_build_object($2, (stats->>$2)::int + $1) WHERE id = $3',
            [task.points, task.category, req.user.id]
        );

        const userResult = await pool.query('SELECT total_points, stats FROM users WHERE id = $1', [req.user.id]);
        const { total_points, stats } = userResult.rows[0];
        const levelThresholds = [0, 100, 300, 600, 1000, 1500, 2100, 3000, 4000, 5500];
        let currentLevel = 1;
        for (let i = 0; i < levelThresholds.length; i++) {
            if (total_points >= levelThresholds[i]) currentLevel = i + 1;
            else break;
        }
        await pool.query('UPDATE users SET current_level = $1 WHERE id = $2', [currentLevel, req.user.id]);

        res.json({ message: 'تم إتمام المهمة بنجاح' });
    } catch (error) {
        console.error('Error completing task:', error);
        res.status(500).json({ error: 'خطأ في إتمام المهمة، حاول لاحقًا' });
    }
});

app.delete('/api/tasks/:id', authenticateToken, async (req, res) => {
    const taskId = req.params.id;
    try {
        const result = await pool.query('DELETE FROM tasks WHERE id = $1 AND user_id = $2', [taskId, req.user.id]);
        if (result.rowCount === 0) {
            return res.status(404).json({ error: 'المهمة غير موجودة أو ليست ملكك' });
        }
        res.json({ message: 'تم حذف المهمة بنجاح' });
    } catch (error) {
        console.error('Error deleting task:', error);
        res.status(500).json({ error: 'خطأ في حذف المهمة، حاول لاحقًا' });
    }
});

// مسار الإحصائيات
app.get('/api/stats', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query('SELECT total_points, current_level, stats FROM users WHERE id = $1', [req.user.id]);
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'المستخدم غير موجود' });
        }
        const { total_points, current_level, stats } = result.rows[0];
        res.json({
            totalPoints: total_points,
            currentLevel: current_level,
            stats: stats || { strength: 0, stamina: 0, intelligence: 0, agility: 0, general: 0 }
        });
    } catch (error) {
        console.error('Error fetching stats:', error);
        res.status(500).json({ error: 'خطأ في جلب الإحصائيات، حاول لاحقًا' });
    }
});

// تصدير لـ Vercel
module.exports = app;
