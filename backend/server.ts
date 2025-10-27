import express from 'express';
import cors from 'cors';
import * as dotenv from 'dotenv';
import path from 'path';
import fs from 'fs';
import { Pool } from 'pg';
import { fileURLToPath } from 'url';
import jwt from 'jsonwebtoken';
import morgan from 'morgan';
import { z } from 'zod';

// Import Zod schemas from schema.ts
import { 
  userSchema, 
  productSchema, 
  createProductInputSchema, 
  updateProductInputSchema 
} from './schema.ts';

dotenv.config();

// ESM workaround for __dirname
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Environment variables
const { 
  DATABASE_URL, 
  PGHOST, 
  PGDATABASE, 
  PGUSER, 
  PGPASSWORD, 
  PGPORT = 5432, 
  JWT_SECRET = 'your-secret-key',
  PORT = 3000 
} = process.env;

// PostgreSQL connection pool setup
const pool = new Pool(
  DATABASE_URL
    ? { 
        connectionString: DATABASE_URL, 
        ssl: { require: true } 
      }
    : {
        host: PGHOST,
        database: PGDATABASE,
        user: PGUSER,
        password: PGPASSWORD,
        port: Number(PGPORT),
        ssl: { require: true },
      }
);

const app = express();

// Error response utility function
interface ErrorResponse {
  success: false;
  message: string;
  error_code?: string;
  details?: any;
  timestamp: string;
}

function createErrorResponse(
  message: string,
  error?: any,
  errorCode?: string
): ErrorResponse {
  const response: ErrorResponse = {
    success: false,
    message,
    timestamp: new Date().toISOString()
  };

  if (errorCode) {
    response.error_code = errorCode;
  }

  if (error) {
    response.details = {
      name: error.name,
      message: error.message,
      stack: error.stack
    };
  }

  return response;
}

// Middleware setup
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:5173',
  credentials: true,
}));

app.use(express.json({ limit: "5mb" }));

// Morgan logging for better development experience
app.use(morgan(':method :url :status :res[content-length] - :response-time ms'));

// Serve static files from the 'public' directory
app.use(express.static(path.join(__dirname, 'public')));

/*
  Authentication middleware for protected routes
  Verifies JWT token and loads user data from database
*/
const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json(createErrorResponse('Access token required', null, 'AUTH_TOKEN_MISSING'));
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const result = await pool.query('SELECT uid, email, name, age, created_at, bio FROM users WHERE uid = $1', [decoded.user_id]);
    
    if (result.rows.length === 0) {
      return res.status(401).json(createErrorResponse('Invalid token - user not found', null, 'AUTH_USER_NOT_FOUND'));
    }

    req.user = result.rows[0];
    next();
  } catch (error) {
    return res.status(403).json(createErrorResponse('Invalid or expired token', error, 'AUTH_TOKEN_INVALID'));
  }
};

/*
  Admin authentication middleware
  Checks if user has admin privileges (for now, all authenticated users are admins)
*/
const authenticateAdmin = async (req, res, next) => {
  // First authenticate the token
  await authenticateToken(req, res, () => {
    // For now, all authenticated users have admin privileges
    // In a real application, you would check user role/permissions
    next();
  });
};

// ===== AUTHENTICATION ENDPOINTS =====

/*
  User registration endpoint
  Creates new user account and returns JWT token for immediate login
*/
app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password, name, age, bio } = req.body;

    // Validation
    if (!email || !password || !name || !age) {
      return res.status(400).json(createErrorResponse('Email, password, name, and age are required', null, 'MISSING_REQUIRED_FIELDS'));
    }

    if (password.length < 6) {
      return res.status(400).json(createErrorResponse('Password must be at least 6 characters long', null, 'PASSWORD_TOO_SHORT'));
    }

    if (age < 13 || age > 120) {
      return res.status(400).json(createErrorResponse('Age must be between 13 and 120', null, 'INVALID_AGE'));
    }

    // Check if user exists
    const existingUser = await pool.query('SELECT uid FROM users WHERE email = $1', [email.toLowerCase().trim()]);
    if (existingUser.rows.length > 0) {
      return res.status(400).json(createErrorResponse('User with this email already exists', null, 'USER_ALREADY_EXISTS'));
    }

    // Generate unique user ID
    const user_id = `user_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;

    // Create user (NO HASHING - store password directly for development)
    const result = await pool.query(
      'INSERT INTO users (uid, email, password_hash, name, age, bio, created_at) VALUES ($1, $2, $3, $4, $5, $6, NOW()) RETURNING uid, email, name, age, created_at, bio',
      [user_id, email.toLowerCase().trim(), password, name.trim(), age, bio?.trim() || null]
    );

    const user = result.rows[0];

    // Generate JWT
    const token = jwt.sign(
      { user_id: user.uid, email: user.email }, 
      JWT_SECRET, 
      { expiresIn: '7d' }
    );

    res.status(201).json({
      message: 'User created successfully',
      user: {
        uid: user.uid,
        email: user.email,
        name: user.name,
        age: user.age,
        created_at: user.created_at,
        bio: user.bio
      },
      token
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json(createErrorResponse('Internal server error', error, 'INTERNAL_SERVER_ERROR'));
  }
});

/*
  User login endpoint
  Authenticates user credentials and returns JWT token
*/
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Validation
    if (!email || !password) {
      return res.status(400).json(createErrorResponse('Email and password are required', null, 'MISSING_REQUIRED_FIELDS'));
    }

    // Find user (NO HASHING - direct password comparison for development)
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email.toLowerCase().trim()]);
    if (result.rows.length === 0) {
      return res.status(400).json(createErrorResponse('Invalid email or password', null, 'INVALID_CREDENTIALS'));
    }

    const user = result.rows[0];

    // Check password (direct comparison for development)
    const is_valid_password = password === user.password_hash;
    if (!is_valid_password) {
      return res.status(400).json(createErrorResponse('Invalid email or password', null, 'INVALID_CREDENTIALS'));
    }

    // Generate JWT
    const token = jwt.sign(
      { user_id: user.uid, email: user.email }, 
      JWT_SECRET, 
      { expiresIn: '7d' }
    );

    res.json({
      message: 'Login successful',
      user: {
        uid: user.uid,
        email: user.email,
        name: user.name,
        age: user.age,
        created_at: user.created_at,
        bio: user.bio
      },
      token
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json(createErrorResponse('Internal server error', error, 'INTERNAL_SERVER_ERROR'));
  }
});

/*
  Token verification endpoint
  Verifies if JWT token is valid and returns user data
*/
app.get('/api/auth/verify', authenticateToken, (req, res) => {
  res.json({
    message: 'Token is valid',
    user: {
      uid: req.user.uid,
      email: req.user.email,
      name: req.user.name,
      age: req.user.age,
      created_at: req.user.created_at,
      bio: req.user.bio
    }
  });
});

// ===== USER ENDPOINTS =====

/*
  Get all users endpoint
  Returns list of all registered users (requires authentication)
*/
app.get('/api/users', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT uid, email, name, age, created_at, bio FROM users ORDER BY created_at DESC');
    
    res.json({
      message: 'Users retrieved successfully',
      users: result.rows,
      total: result.rows.length
    });
  } catch (error) {
    console.error('Get users error:', error);
    res.status(500).json(createErrorResponse('Internal server error', error, 'INTERNAL_SERVER_ERROR'));
  }
});

/*
  Get specific user by ID endpoint
  Returns user details for specified user_id (requires authentication)
*/
app.get('/api/users/:user_id', authenticateToken, async (req, res) => {
  try {
    const { user_id } = req.params;

    if (!user_id) {
      return res.status(400).json(createErrorResponse('User ID is required', null, 'MISSING_USER_ID'));
    }

    const result = await pool.query('SELECT uid, email, name, age, created_at, bio FROM users WHERE uid = $1', [user_id]);
    
    if (result.rows.length === 0) {
      return res.status(404).json(createErrorResponse('User not found', null, 'USER_NOT_FOUND'));
    }

    res.json({
      message: 'User retrieved successfully',
      user: result.rows[0]
    });
  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).json(createErrorResponse('Internal server error', error, 'INTERNAL_SERVER_ERROR'));
  }
});

// ===== PRODUCT ENDPOINTS =====

/*
  Get all products endpoint
  Returns list of all products (public access, no authentication required)
*/
app.get('/api/products', async (req, res) => {
  try {
    const result = await pool.query('SELECT id, title, price, in_stock, created_at, description FROM products ORDER BY created_at DESC');
    
    res.json({
      message: 'Products retrieved successfully',
      products: result.rows,
      total: result.rows.length
    });
  } catch (error) {
    console.error('Get products error:', error);
    res.status(500).json(createErrorResponse('Internal server error', error, 'INTERNAL_SERVER_ERROR'));
  }
});

/*
  Create new product endpoint
  Creates a new product entry (requires admin authentication)
*/
app.post('/api/products', authenticateAdmin, async (req, res) => {
  try {
    // Validate request body against Zod schema
    const validatedData = createProductInputSchema.parse(req.body);
    const { title, price, in_stock, description } = validatedData;

    // Generate unique product ID
    const product_id = `prod_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;

    // Insert new product
    const result = await pool.query(
      'INSERT INTO products (id, title, price, in_stock, description, created_at) VALUES ($1, $2, $3, $4, $5, NOW()) RETURNING id, title, price, in_stock, created_at, description',
      [product_id, title, price, in_stock, description || null]
    );

    const product = result.rows[0];

    res.status(201).json({
      message: 'Product created successfully',
      product: product
    });
  } catch (error) {
    if (error instanceof z.ZodError) {
      return res.status(400).json(createErrorResponse('Invalid input data', error.errors, 'VALIDATION_ERROR'));
    }
    console.error('Create product error:', error);
    res.status(500).json(createErrorResponse('Internal server error', error, 'INTERNAL_SERVER_ERROR'));
  }
});

/*
  Get specific product by ID endpoint
  Returns product details for specified product_id (public access)
*/
app.get('/api/products/:product_id', async (req, res) => {
  try {
    const { product_id } = req.params;

    if (!product_id) {
      return res.status(400).json(createErrorResponse('Product ID is required', null, 'MISSING_PRODUCT_ID'));
    }

    const result = await pool.query('SELECT id, title, price, in_stock, created_at, description FROM products WHERE id = $1', [product_id]);
    
    if (result.rows.length === 0) {
      return res.status(404).json(createErrorResponse('Product not found', null, 'PRODUCT_NOT_FOUND'));
    }

    res.json({
      message: 'Product retrieved successfully',
      product: result.rows[0]
    });
  } catch (error) {
    console.error('Get product error:', error);
    res.status(500).json(createErrorResponse('Internal server error', error, 'INTERNAL_SERVER_ERROR'));
  }
});

/*
  Update product endpoint
  Updates existing product by product_id (requires admin authentication)
*/
app.put('/api/products/:product_id', authenticateAdmin, async (req, res) => {
  try {
    const { product_id } = req.params;

    if (!product_id) {
      return res.status(400).json(createErrorResponse('Product ID is required', null, 'MISSING_PRODUCT_ID'));
    }

    // Validate request body against Zod schema
    const validatedData = updateProductInputSchema.parse(req.body);
    const { title, price, in_stock, description } = validatedData;

    // Check if product exists
    const existingProduct = await pool.query('SELECT id FROM products WHERE id = $1', [product_id]);
    if (existingProduct.rows.length === 0) {
      return res.status(404).json(createErrorResponse('Product not found', null, 'PRODUCT_NOT_FOUND'));
    }

    // Update product
    const result = await pool.query(
      'UPDATE products SET title = $1, price = $2, in_stock = $3, description = $4 WHERE id = $5 RETURNING id, title, price, in_stock, created_at, description',
      [title, price, in_stock, description || null, product_id]
    );

    res.json({
      message: 'Product updated successfully',
      product: result.rows[0]
    });
  } catch (error) {
    if (error instanceof z.ZodError) {
      return res.status(400).json(createErrorResponse('Invalid input data', error.errors, 'VALIDATION_ERROR'));
    }
    console.error('Update product error:', error);
    res.status(500).json(createErrorResponse('Internal server error', error, 'INTERNAL_SERVER_ERROR'));
  }
});

/*
  Delete product endpoint
  Deletes product by product_id (requires admin authentication)
*/
app.delete('/api/products/:product_id', authenticateAdmin, async (req, res) => {
  try {
    const { product_id } = req.params;

    if (!product_id) {
      return res.status(400).json(createErrorResponse('Product ID is required', null, 'MISSING_PRODUCT_ID'));
    }

    // Check if product exists
    const existingProduct = await pool.query('SELECT id FROM products WHERE id = $1', [product_id]);
    if (existingProduct.rows.length === 0) {
      return res.status(404).json(createErrorResponse('Product not found', null, 'PRODUCT_NOT_FOUND'));
    }

    // Delete product
    await pool.query('DELETE FROM products WHERE id = $1', [product_id]);

    res.status(204).send(); // No content response for successful deletion
  } catch (error) {
    console.error('Delete product error:', error);
    res.status(500).json(createErrorResponse('Internal server error', error, 'INTERNAL_SERVER_ERROR'));
  }
});

// ===== HEALTH CHECK =====

/*
  Health check endpoint
  Returns server status and database connectivity
*/
app.get('/api/health', async (req, res) => {
  try {
    // Test database connection
    await pool.query('SELECT 1');
    res.json({ 
      status: 'ok', 
      timestamp: new Date().toISOString(),
      database: 'connected'
    });
  } catch (error) {
    res.status(500).json({ 
      status: 'error', 
      timestamp: new Date().toISOString(),
      database: 'disconnected',
      error: error.message
    });
  }
});

// ===== SPA ROUTING =====

// Catch-all route for SPA routing (serves index.html for non-API routes)
app.get(/^(?!\/api).*/, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Export app and pool for external use
export { app, pool };

// Start the server
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on port ${PORT} and listening on 0.0.0.0`);
  console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`Database connection: ${DATABASE_URL ? 'Using DATABASE_URL' : 'Using individual DB params'}`);
});