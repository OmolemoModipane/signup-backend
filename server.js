const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mysql = require('mysql2');
const { OAuth2Client } = require('google-auth-library');
require('dotenv').config();
const cors = require('cors');

const app = express();

// Middleware
app.use(express.json());
app.use(cors({
  origin: ['https://ruix-signup.vercel.app', 'http://localhost:3000'] 
}));

// Database connection
const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT,
});

db.connect(err => {
  if (err) {
    console.error('Database connection error:', err);
    process.exit(1);
  }
  console.log("MySQL Connected...");
});

// JWT Secret Key
const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret_key';

// Google OAuth2 Client
const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

// Middleware to protect routes
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Bearer <token>

  if (!token) return res.status(401).json({ message: 'Access denied' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: 'Invalid token' });
    req.user = user;
    next();
  });
};

// Route to handle user registration
app.post('/register', async (req, res) => {
  const { name, email, password } = req.body;

  // Validate email format
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return res.status(400).json({ message: 'Invalid email format' });
  }

  // Validate password criteria
  if (password.length < 8 || !/\d/.test(password)) {
    return res.status(400).json({ message: 'Password must be at least 8 characters long and contain at least one number' });
  }

  try {
    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert user into the database
    db.query(
      'INSERT INTO users (name, email, password) VALUES (?, ?, ?)',
      [name, email, hashedPassword],
      (err, result) => {
        if (err) {
          console.error('Database insertion error:', err);
          return res.status(500).json({ message: 'Database error' });
        }

        // Generate a token
        const token = jwt.sign({ userId: result.insertId, email }, JWT_SECRET, { expiresIn: '1h' });

        res.status(201).json({ message: 'User registered successfully', token });
      }
    );
  } catch (error) {
    console.error('Internal server error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Route to handle user login
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  // Find the user in the database
  db.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
    if (err) {
      console.error('Database query error:', err);
      return res.status(500).json({ message: 'Database error' });
    }

    if (results.length === 0) return res.status(400).json({ message: 'User not found' });

    const user = results[0];

    // Compare the provided password with the stored hashed password
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) return res.status(401).json({ message: 'Invalid password' });

    // Generate a token
    const token = jwt.sign({ userId: user.id, email: user.email }, JWT_SECRET, { expiresIn: '1h' });

    res.json({ message: 'Login successful', token });
  });
});

// Route to handle Google Sign-In
app.post('/auth/google', async (req, res) => {
  const { token } = req.body;

  try {
    // Verify the Google ID token
    const ticket = await client.verifyIdToken({
      idToken: token,
      audience: process.env.GOOGLE_CLIENT_ID,
    });
    
    const payload = ticket.getPayload();
    const userId = payload['sub'];
    const email = payload['email'];
    const name = payload['name'];

    // Check if the user exists in the database
    db.query('SELECT * FROM users WHERE email = ?', [email], (err, results) => {
      if (err) {
        console.error('Database query error:', err);
        return res.status(500).json({ message: 'Database error' });
      }

      if (results.length === 0) {
        // If the user does not exist, insert them into the database
        db.query(
          'INSERT INTO users (name, email) VALUES (?, ?)',
          [name, email],
          (err, result) => {
            if (err) {
              console.error('Database insertion error:', err);
              return res.status(500).json({ message: 'Database error' });
            }

            // Generate a token
            const token = jwt.sign({ userId: result.insertId, email }, JWT_SECRET, { expiresIn: '1h' });

            res.json({ message: 'User created and authenticated successfully', token });
          }
        );
      } else {
        // If the user exists, generate a token
        const token = jwt.sign({ userId: results[0].id, email }, JWT_SECRET, { expiresIn: '1h' });

        res.json({ message: 'User authenticated successfully', token });
      }
    });
  } catch (error) {
    console.error('Error during Google authentication:', error);
    res.status(401).json({ message: 'Invalid token' });
  }
});

// Example of a protected route
app.get('/protected', authenticateToken, (req, res) => {
  res.json({ message: `Hello ${req.user.email}, you are authenticated!` });
});

// Server listener
const PORT = process.env.PORT || 5001;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
