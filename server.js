// Load environment variables from .env file
require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs'); // Using bcryptjs
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
app.use(cors()); // Enable CORS for all origins
app.use(express.json()); // Middleware to parse JSON bodies

// --- Environment Variable Check ---
if (!process.env.DATABASE_URL) {
    console.error('FATAL ERROR: DATABASE_URL environment variable is not set.');
    process.exit(1); // Exit if database URL is missing
}
if (!process.env.JWT_SECRET) {
    console.error('FATAL ERROR: JWT_SECRET environment variable is not set.');
    process.exit(1); // Exit if JWT secret is missing
}
console.log('Environment variables loaded successfully.');

// --- Neon Database Connection Pool ---
// Ensure SSL is configured correctly for Neon (rejectUnauthorized: false is often needed for free tiers)
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false // Adjust if necessary based on Neon's requirements
    }
});

// --- Test Database Connection on Startup ---
pool.connect((err, client, release) => {
    if (err) {
        console.error('DATABASE CONNECTION FAILED:', err.message, err.stack);
        // Decide if the app should exit or try to continue
        // For critical apps, exiting might be safer: process.exit(1);
        // For now, we log the error and let the app start, but endpoints needing DB will fail.
    } else {
        console.log('Successfully connected to Neon database.');
        client.query('SELECT NOW()', (err, result) => {
            release(); // Release the client back to the pool
            if (err) {
                console.error('Error executing test query:', err.stack);
            } else {
                console.log('Test query successful. Current DB time:', result.rows[0].now);
            }
        });
    }
});

// --- Database Initialization Function ---
async function initializeDatabase() {
    console.log('Attempting to initialize database schema...');
    const client = await pool.connect(); // Get a client from the pool
    try {
        await client.query('BEGIN'); // Start transaction

        // Create users table if it doesn't exist
        await client.query(`
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                email VARCHAR(255) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL,
                total_points INTEGER DEFAULT 0,
                current_level INTEGER DEFAULT 1,
                stats JSONB DEFAULT '{"strength": 0, "stamina": 0, "intelligence": 0, "agility": 0, "general": 0}'::jsonb
            );
        `);
        console.log('Users table checked/created.');

        // Create tasks table if it doesn't exist
        await client.query(`
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
        console.log('Tasks table checked/created.');

        await client.query('COMMIT'); // Commit transaction
        console.log('Database schema initialization successful.');
    } catch (error) {
        await client.query('ROLLBACK'); // Rollback transaction on error
        console.error('DATABASE INITIALIZATION FAILED:', error.message, error.stack);
        // Depending on the severity, you might want to exit: process.exit(1);
    } finally {
        client.release(); // ALWAYS release the client
        console.log('Database initialization process finished.');
    }
}

// --- Run Database Initialization ---
// We wrap this in a try/catch in case the connection itself fails badly
try {
    initializeDatabase().catch(err => {
        console.error("Unhandled error during async database initialization:", err);
        // process.exit(1); // Optional: exit if DB init is critical
    });
} catch (syncError) {
    console.error("Synchronous error calling initializeDatabase:", syncError);
    // process.exit(1); // Optional: exit if DB init is critical
}


// --- Authentication Middleware ---
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

    if (!token) {
        console.log('Auth middleware: No token provided.');
        // Use 401 Unauthorized for missing credentials
        return res.status(401).json({ error: 'التوكن غير موجود (No token provided)' });
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) {
            console.log('Auth middleware: Invalid or expired token.', err.message);
            // Use 403 Forbidden for invalid/expired credentials
            return res.status(403).json({ error: 'التوكن غير صالح أو منتهي الصلاحية (Invalid/Expired token)' });
        }
        // Add user payload (e.g., { id: userId }) to the request object
        req.user = user;
        console.log(`Auth middleware: Token verified for user ID: ${user.id}`);
        next(); // Proceed to the next middleware or route handler
    });
};

// === API Endpoints ===

// --- Health Check Endpoint ---
app.get('/api/health', (req, res) => {
    console.log('Health check requested.');
    res.status(200).json({ status: 'OK', message: 'Server is running', timestamp: new Date().toISOString() });
});

// --- Database Health Check Endpoint ---
app.get('/api/db-health', async (req, res) => {
    console.log('Database health check requested.');
    try {
        const client = await pool.connect();
        try {
            const result = await client.query('SELECT NOW() as now');
            res.status(200).json({ status: 'OK', message: 'Database connection successful.', dbTime: result.rows[0].now });
        } finally {
            client.release(); // Ensure client is always released
        }
    } catch (error) {
        console.error('Database health check FAILED:', error.message, error.stack);
        res.status(500).json({ status: 'Error', message: 'Failed to connect to database.', error: error.message });
    }
});


// --- User Signup Endpoint ---
app.post('/api/auth/signup', async (req, res) => {
    const { email, password } = req.body;
    console.log(`Signup attempt received for email: ${email}`);

    // Basic Input Validation
    if (!email || !password) {
        console.log('Signup failed: Missing email or password.');
        return res.status(400).json({ error: 'البريد الإلكتروني وكلمة المرور مطلوبان (Email and password required)' });
    }
    if (password.length < 6) {
        console.log(`Signup failed for ${email}: Password too short.`);
        return res.status(400).json({ error: 'كلمة المرور يجب أن تكون 6 أحرف على الأقل (Password must be at least 6 characters)' });
    }

    let hashedPassword;
    try {
        console.log(`Hashing password for ${email}...`);
        hashedPassword = await bcrypt.hash(password, 10); // Use 10-12 rounds for salt
        console.log(`Password hashed successfully for ${email}.`);
    } catch (hashError) {
        console.error(`Password hashing failed for ${email}:`, hashError.message, hashError.stack);
        return res.status(500).json({ error: 'خطأ داخلي في الخادم (Internal server error during hashing)' });
    }

    let client; // Declare client outside try block to use in finally
    try {
        console.log(`Attempting to insert user ${email} into database...`);
        client = await pool.connect(); // Get connection from pool
        const result = await client.query(
            'INSERT INTO users (email, password) VALUES ($1, $2) RETURNING id',
            [email, hashedPassword]
        );
        const userId = result.rows[0].id;
        console.log(`User ${email} inserted successfully with ID: ${userId}.`);

        console.log(`Generating JWT for user ID: ${userId}...`);
        const token = jwt.sign(
            { id: userId, email: email }, // Include relevant, non-sensitive info in payload
            process.env.JWT_SECRET,
            { expiresIn: '1d' } // Token expires in 1 day
        );
        console.log(`JWT generated successfully for ${email}.`);

        res.status(201).json({ token, userId }); // Return 201 Created status

    } catch (dbError) {
        console.error(`Database error during signup for ${email}:`, dbError.message, dbError.stack);
        if (dbError.code === '23505') { // Unique violation (email already exists)
            console.log(`Signup failed for ${email}: Email already exists.`);
            return res.status(409).json({ error: 'البريد الإلكتروني مستخدم بالفعل (Email already exists)' }); // Use 409 Conflict
        }
        // Generic server error for other database issues
        return res.status(500).json({ error: 'خطأ في الخادم أثناء تسجيل الحساب (Server error during signup)' });
    } finally {
        if (client) {
            client.release(); // Release the client back to the pool if it was acquired
            console.log(`Database client released for ${email} signup request.`);
        }
    }
});

// --- User Signin Endpoint ---
app.post('/api/auth/signin', async (req, res) => {
    const { email, password } = req.body;
    console.log(`Signin attempt received for email: ${email}`);

    if (!email || !password) {
        console.log('Signin failed: Missing email or password.');
        return res.status(400).json({ error: 'البريد الإلكتروني وكلمة المرور مطلوبان (Email and password required)' });
    }

    let client;
    try {
        console.log(`Fetching user data for ${email}...`);
        client = await pool.connect();
        const result = await client.query('SELECT id, email, password FROM users WHERE email = $1', [email]);

        if (result.rows.length === 0) {
            console.log(`Signin failed: User not found for email ${email}.`);
            // Use 401 Unauthorized for incorrect credentials
            return res.status(401).json({ error: 'البريد الإلكتروني أو كلمة المرور غير صحيحة (Invalid email or password)' });
        }

        const user = result.rows[0];
        console.log(`User found for ${email}. Comparing password...`);

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            console.log(`Signin failed: Invalid password for email ${email}.`);
            // Use 401 Unauthorized
            return res.status(401).json({ error: 'البريد الإلكتروني أو كلمة المرور غير صحيحة (Invalid email or password)' });
        }

        console.log(`Password verified for ${email}. Generating JWT...`);
        const token = jwt.sign(
            { id: user.id, email: user.email },
            process.env.JWT_SECRET,
            { expiresIn: '1d' }
        );
        console.log(`JWT generated successfully for ${email}.`);

        res.json({ token, userId: user.id }); // Return token and user ID

    } catch (error) {
        console.error(`Error during signin for ${email}:`, error.message, error.stack);
        res.status(500).json({ error: 'خطأ في الخادم أثناء تسجيل الدخول (Server error during signin)' });
    } finally {
        if (client) {
            client.release();
            console.log(`Database client released for ${email} signin request.`);
        }
    }
});

// --- Verify User Endpoint (Get Current User) ---
app.get('/api/auth/me', authenticateToken, async (req, res) => {
    // The user ID is available from the authenticateToken middleware via req.user.id
    const userId = req.user.id;
    console.log(`Fetching user data for authenticated user ID: ${userId}`);

    let client;
    try {
        client = await pool.connect();
        // Select only necessary, non-sensitive fields
        const result = await client.query('SELECT id, email, total_points, current_level, stats FROM users WHERE id = $1', [userId]);

        if (result.rows.length === 0) {
            console.error(`Authenticated user ID ${userId} not found in database.`);
            // This shouldn't happen if the token is valid, indicates a data inconsistency
            return res.status(404).json({ error: 'المستخدم غير موجود (User not found)' });
        }

        const user = result.rows[0];
        console.log(`User data fetched successfully for user ID: ${userId}`);
        // Return relevant user data (excluding password)
        res.json({
            userId: user.id,
            email: user.email,
            totalPoints: user.total_points,
            currentLevel: user.current_level,
            stats: user.stats
        });
    } catch (error) {
        console.error(`Error fetching data for user ID ${userId}:`, error.message, error.stack);
        res.status(500).json({ error: 'خطأ في الخادم، حاول لاحقًا (Server error fetching user data)' });
    } finally {
        if (client) {
            client.release();
            console.log(`Database client released for user ID ${userId} 'me' request.`);
        }
    }
});


// --- Add Task Endpoint ---
app.post('/api/tasks', authenticateToken, async (req, res) => {
    const userId = req.user.id;
    const { id, title, description, difficulty, difficulty_text, category, category_text, category_icon_class, points, completed = false } = req.body; // Default completed to false
    console.log(`Adding task request received for user ID: ${userId}, Task ID: ${id}`);

    // Validate required fields
    if (!id || !title || !difficulty || !difficulty_text || !category || !category_text || !category_icon_class || points === undefined || points === null) {
        console.log(`Add task failed for user ${userId}: Missing required fields.`);
        return res.status(400).json({ error: 'بعض الحقول المطلوبة مفقودة (Missing required task fields)' });
    }
    if (typeof points !== 'number' || points < 0) {
        console.log(`Add task failed for user ${userId}: Invalid points value.`);
        return res.status(400).json({ error: 'قيمة النقاط غير صالحة (Invalid points value)' });
    }

    let client;
    try {
        console.log(`Inserting task ${id} for user ${userId}...`);
        client = await pool.connect();
        await client.query(
            `INSERT INTO tasks (id, user_id, title, description, difficulty, difficulty_text, category, category_text, category_icon_class, points, completed)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
            [id, userId, title, description, difficulty, difficulty_text, category, category_text, category_icon_class, points, completed]
        );
        console.log(`Task ${id} added successfully for user ${userId}.`);
        res.status(201).json({ message: 'تم إضافة المهمة بنجاح (Task added successfully)', taskId: id }); // Return 201 Created
    } catch (error) {
        console.error(`Error adding task ${id} for user ${userId}:`, error.message, error.stack);
        // Check for potential duplicate task ID error (if ID is meant to be unique per user or globally)
        if (error.code === '23505') { // Primary key violation
             console.log(`Add task failed for user ${userId}: Task ID ${id} already exists.`);
             return res.status(409).json({ error: 'معرف المهمة مستخدم بالفعل (Task ID already exists)'});
        }
        res.status(500).json({ error: 'خطأ في الخادم أثناء إضافة المهمة (Server error adding task)' });
    } finally {
        if (client) {
            client.release();
            console.log(`Database client released for user ${userId} add task request.`);
        }
    }
});

// --- Get Tasks Endpoint ---
app.get('/api/tasks', authenticateToken, async (req, res) => {
    const userId = req.user.id;
    console.log(`Fetching tasks for user ID: ${userId}`);

    let client;
    try {
        client = await pool.connect();
        const result = await client.query('SELECT * FROM tasks WHERE user_id = $1 ORDER BY completed ASC, id DESC', [userId]); // Example ordering
        console.log(`Found ${result.rows.length} tasks for user ID: ${userId}.`);
        res.json(result.rows);
    } catch (error) {
        console.error(`Error fetching tasks for user ID ${userId}:`, error.message, error.stack);
        res.status(500).json({ error: 'خطأ في الخادم أثناء جلب المهام (Server error fetching tasks)' });
    } finally {
        if (client) {
            client.release();
            console.log(`Database client released for user ${userId} get tasks request.`);
        }
    }
});

// --- Complete Task Endpoint ---
app.patch('/api/tasks/:id/complete', authenticateToken, async (req, res) => {
    const taskId = req.params.id;
    const userId = req.user.id;
    console.log(`Attempting to complete task ID: ${taskId} for user ID: ${userId}`);

    let client;
    try {
        client = await pool.connect();
        await client.query('BEGIN'); // Start transaction

        // 1. Find the task and ensure it belongs to the user and is not completed
        console.log(`Fetching task ${taskId} for user ${userId}...`);
        const taskResult = await client.query(
            'SELECT id, user_id, points, category, completed FROM tasks WHERE id = $1 AND user_id = $2 FOR UPDATE', // Lock the row
            [taskId, userId]
        );

        if (taskResult.rows.length === 0) {
            await client.query('ROLLBACK');
            console.log(`Complete task failed: Task ${taskId} not found or does not belong to user ${userId}.`);
            return res.status(404).json({ error: 'المهمة غير موجودة أو لا تملك الصلاحية (Task not found or unauthorized)' });
        }

        const task = taskResult.rows[0];
        if (task.completed) {
            await client.query('ROLLBACK');
            console.log(`Complete task failed: Task ${taskId} is already completed.`);
            return res.status(400).json({ error: 'المهمة مكتملة بالفعل (Task already completed)' });
        }

        // 2. Mark the task as completed
        console.log(`Marking task ${taskId} as completed...`);
        await client.query('UPDATE tasks SET completed = TRUE WHERE id = $1 AND user_id = $2', [taskId, userId]);

        // 3. Fetch current user stats
        console.log(`Fetching current stats for user ${userId}...`);
        const userResult = await client.query(
            'SELECT id, total_points, current_level, stats FROM users WHERE id = $1 FOR UPDATE', // Lock the user row
            [userId]
        );
        const user = userResult.rows[0]; // Assuming user must exist if they have tasks

        // 4. Calculate new points, stats, and level
        const pointsEarned = task.points;
        const category = task.category;
        const newTotalPoints = user.total_points + pointsEarned;

        // Deep copy stats to avoid modifying the original object directly if needed elsewhere
        const currentStats = user.stats ? JSON.parse(JSON.stringify(user.stats)) : {};
        currentStats[category] = (currentStats[category] || 0) + pointsEarned;

        // Define level thresholds (example)
        const levelThresholds = [0, 100, 300, 600, 1000, 1500, 2100, 3000, 4000, 5500]; // Level 1 at 0, Level 2 at 100, etc.
        let newLevel = user.current_level;
        // Find the highest level threshold the user meets or exceeds
        for (let i = levelThresholds.length - 1; i >= 0; i--) {
            if (newTotalPoints >= levelThresholds[i]) {
                newLevel = i + 1; // Levels are 1-based index + 1
                break;
            }
        }
        const levelChanged = newLevel !== user.current_level;
        console.log(`User ${userId}: Points ${user.total_points} -> ${newTotalPoints}, Level ${user.current_level} -> ${newLevel}, Stats updated for ${category}.`);

        // 5. Update user stats
        console.log(`Updating user stats for user ${userId}...`);
        await client.query(
            'UPDATE users SET total_points = $1, current_level = $2, stats = $3::jsonb WHERE id = $4',
            [newTotalPoints, newLevel, JSON.stringify(currentStats), userId]
        );

        await client.query('COMMIT'); // Commit transaction
        console.log(`Task ${taskId} completed and user ${userId} stats updated successfully.`);
        res.json({
             message: 'تم إتمام المهمة بنجاح (Task completed successfully)',
             pointsEarned: pointsEarned,
             newTotalPoints: newTotalPoints,
             newLevel: newLevel,
             levelChanged: levelChanged,
             updatedStats: currentStats
        });

    } catch (error) {
        if (client) await client.query('ROLLBACK'); // Rollback on any error
        console.error(`Error completing task ${taskId} for user ${userId}:`, error.message, error.stack);
        res.status(500).json({ error: 'خطأ في الخادم أثناء إتمام المهمة (Server error completing task)' });
    } finally {
        if (client) {
            client.release();
            console.log(`Database client released for user ${userId} complete task request.`);
        }
    }
});

// --- Delete Task Endpoint ---
app.delete('/api/tasks/:id', authenticateToken, async (req, res) => {
    const taskId = req.params.id;
    const userId = req.user.id;
    console.log(`Attempting to delete task ID: ${taskId} for user ID: ${userId}`);

    let client;
    try {
        client = await pool.connect();
        // Ensure the task belongs to the user before deleting
        const result = await client.query('DELETE FROM tasks WHERE id = $1 AND user_id = $2 RETURNING id', [taskId, userId]);

        if (result.rowCount === 0) {
            console.log(`Delete task failed: Task ${taskId} not found or does not belong to user ${userId}.`);
            // Use 404 Not Found if the resource doesn't exist for this user
            return res.status(404).json({ error: 'المهمة غير موجودة أو لا تملك الصلاحية (Task not found or unauthorized)' });
        }

        console.log(`Task ${taskId} deleted successfully for user ${userId}.`);
        res.json({ message: 'تم حذف المهمة بنجاح (Task deleted successfully)', deletedTaskId: taskId }); // 200 OK is standard for successful DELETE
    } catch (error) {
        console.error(`Error deleting task ${taskId} for user ${userId}:`, error.message, error.stack);
        res.status(500).json({ error: 'خطأ في الخادم أثناء حذف المهمة (Server error deleting task)' });
    } finally {
        if (client) {
            client.release();
            console.log(`Database client released for user ${userId} delete task request.`);
        }
    }
});

// --- Get Stats Endpoint ---
// This is largely redundant if /api/auth/me returns stats, but kept for compatibility if needed
app.get('/api/stats', authenticateToken, async (req, res) => {
    const userId = req.user.id;
    console.log(`Fetching stats for user ID: ${userId}`);

    let client;
    try {
        client = await pool.connect();
        const result = await client.query('SELECT total_points, current_level, stats FROM users WHERE id = $1', [userId]);

        if (result.rows.length === 0) {
            console.error(`Stats request failed: User ID ${userId} not found.`);
            return res.status(404).json({ error: 'المستخدم غير موجود (User not found)' });
        }

        const { total_points, current_level, stats } = result.rows[0];
        console.log(`Stats fetched successfully for user ID: ${userId}.`);
        res.json({
            totalPoints: total_points,
            currentLevel: current_level,
            stats: stats
        });
    } catch (error) {
        console.error(`Error fetching stats for user ID ${userId}:`, error.message, error.stack);
        res.status(500).json({ error: 'خطأ في الخادم أثناء جلب الإحصائيات (Server error fetching stats)' });
    } finally {
        if (client) {
            client.release();
            console.log(`Database client released for user ${userId} stats request.`);
        }
    }
});


// --- Global Error Handler (Optional but Recommended) ---
// Catches errors not handled in specific routes
app.use((err, req, res, next) => {
    console.error("Unhandled Error:", err.message, err.stack);
    // Avoid sending stack trace to client in production
    res.status(500).json({ error: 'حدث خطأ غير متوقع في الخادم (An unexpected server error occurred)' });
});

// --- Start Server ---
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server listening on port ${PORT}`);
    console.log(`Access health check at: http://localhost:${PORT}/api/health`);
    console.log(`Access DB health check at: http://localhost:${PORT}/api/db-health`);
});
