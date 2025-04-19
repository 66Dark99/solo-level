const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());

// Neon database connection
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

// Middleware to verify JWT
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.sendStatus(401);

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

// Authentication routes
app.post('/api/auth/signin', async (req, res) => {
    const { email, password } = req.body;
    try {
        const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        const user = result.rows[0];
        if (!user) return res.status(404).json({ error: 'المستخدم غير موجود' });

        const match = await bcrypt.compare(password, user.password);
        if (!match) return res.status(401).json({ error: 'كلمة المرور غير صحيحة' });

        const token = jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '1h' });
        res.json({ token });
    } catch (error) {
        console.error('Signin error:', error);
        res.status(500).json({ error: 'خطأ في الخادم' });
    }
});

app.post('/api/auth/signup', async (req, res) => {
    const { email, password } = req.body;
    try {
        const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        if (result.rows.length > 0) {
            return res.status(400).json({ error: 'البريد الإلكتروني مسجل مسبقًا' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = await pool.query(
            'INSERT INTO users (email, password) VALUES ($1, $2) RETURNING id, email',
            [email, hashedPassword]
        );

        const token = jwt.sign({ id: newUser.rows[0].id, email: newUser.rows[0].email }, process.env.JWT_SECRET, { expiresIn: '1h' });
        res.status(201).json({ token });
    } catch (error) {
        console.error('Signup error:', error);
        res.status(500).json({ error: 'خطأ في الخادم' });
    }
});

// Task routes
app.get('/api/tasks', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM tasks WHERE user_id = $1', [req.user.id]);
        res.json(result.rows);
    } catch (error) {
        console.error('Error fetching tasks:', error);
        res.status(500).json({ error: 'خطأ في الخادم' });
    }
});

app.post('/api/tasks', authenticateToken, async (req, res) => {
    const taskData = req.body;
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
        res.status(201).json({ message: 'تم إضافة المهمة' });
    } catch (error) {
        console.error('Error creating task:', error);
        res.status(500).json({ error: 'خطأ في الخادم' });
    }
});

app.patch('/api/tasks/:id/complete', authenticateToken, async (req, res) => {
    const taskId = req.params.id;
    try {
        const result = await pool.query('UPDATE tasks SET completed = true WHERE id = $1 AND user_id = $2 RETURNING *', [taskId, req.user.id]);
        if (result.rows.length === 0) return res.status(404).json({ error: 'المهمة غير موجودة' });

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

        res.json({ message: 'تم إتمام المهمة' });
    } catch (error) {
        console.error('Error completing task:', error);
        res.status(500).json({ error: 'خطأ في الخادم' });
    }
});

app.delete('/api/tasks/:id', authenticateToken, async (req, res) => {
    const taskId = req.params.id;
    try {
        const result = await pool.query('DELETE FROM tasks WHERE id = $1 AND user_id = $2', [taskId, req.user.id]);
        if (result.rowCount === 0) return res.status(404).json({ error: 'المهمة غير موجودة' });
        res.json({ message: 'تم حذف المهمة' });
    } catch (error) {
        console.error('Error deleting task:', error);
        res.status(500).json({ error: 'خطأ في الخادم' });
    }
});

// Stats route
app.get('/api/stats', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query('SELECT total_points, current_level, stats FROM users WHERE id = $1', [req.user.id]);
        if (result.rows.length === 0) return res.status(404).json({ error: 'المستخدم غير موجود' });
        const { total_points, current_level, stats } = result.rows[0];
        res.json({
            totalPoints: total_points,
            currentLevel: current_level,
            stats: stats || { strength: 0, stamina: 0, intelligence: 0, agility: 0, general: 0 }
        });
    } catch (error) {
        console.error('Error fetching stats:', error);
        res.status(500).json({ error: 'خطأ في الخادم' });
    }
});

// Vercel serverless function export
module.exports = app;