const express = require("express");
const mysql = require("mysql2/promise");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const dotenv = require("dotenv");
const bodyParser = require("body-parser");

dotenv.config();

const app = express();
app.use(express.json());
app.use(bodyParser.json());

// Database connection pool
const db = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});

// Middleware for JWT authentication
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) return res.status(401).send("Access Denied");

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).send("Invalid Token");
    req.user = user;
    next();
  });
};

// Initialize database tables
const initializeDatabase = async () => {
  try {
    await db.query(`
      CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(50) NOT NULL UNIQUE,
        name VARCHAR(100) NOT NULL,
        password VARCHAR(255) NOT NULL,
        gender VARCHAR(10),
        location VARCHAR(100),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    await db.query(`
      CREATE TABLE IF NOT EXISTS customers (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        email VARCHAR(100) NOT NULL UNIQUE,
        phone VARCHAR(20) NOT NULL,
        company VARCHAR(100),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        user_id INT,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      );
    `);

    console.log("Database tables initialized successfully!");
  } catch (error) {
    console.error("Error initializing database:", error);
  }
};

// User Registration
app.post("/register", async (req, res) => {
  const { username, name, password, gender, location } = req.body;

  if (!username || !name || !password) {
    return res.status(400).send("Missing required fields");
  }

  const hashedPassword = await bcrypt.hash(password, 10);

  try {
    const [existingUser] = await db.query(
      "SELECT * FROM users WHERE username = ?",
      [username]
    );
    if (existingUser.length > 0) {
      return res.status(400).send("User already exists");
    }

    await db.query(
      "INSERT INTO users (username, name, password, gender, location) VALUES (?, ?, ?, ?, ?)",
      [username, name, hashedPassword, gender, location]
    );

    res.send("User created successfully");
  } catch (error) {
    console.error(error);
    res.status(500).send("Error creating user");
  }
});

// User Login
app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  try {
    const [users] = await db.query("SELECT * FROM users WHERE username = ?", [
      username,
    ]);
    const user = users[0];

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(400).send("Invalid username or password");
    }

    const token = jwt.sign(
      { id: user.id, username: user.username },
      process.env.JWT_SECRET,
      {
        expiresIn: "1h",
      }
    );

    res.json({ token });
  } catch (error) {
    console.error(error);
    res.status(500).send("Error logging in");
  }
});

// Add Customer
app.post("/customers", authenticateToken, async (req, res) => {
  const { name, email, phone, company } = req.body;

  if (!name || !email || !phone) {
    return res.status(400).send("Missing required fields");
  }

  try {
    await db.query(
      "INSERT INTO customers (name, email, phone, company, user_id) VALUES (?, ?, ?, ?, ?)",
      [name, email, phone, company, req.user.id]
    );
    res.send("Customer added successfully");
  } catch (error) {
    console.error(error);
    res.status(500).send("Error adding customer");
  }
});

// Get Customers
app.get("/customers", authenticateToken, async (req, res) => {
  try {
    const [customers] = await db.query(
      "SELECT * FROM customers WHERE user_id = ?",
      [req.user.id]
    );
    res.json(customers);
  } catch (error) {
    console.error(error);
    res.status(500).send("Error retrieving customers");
  }
});

// Update Customer
app.put("/customers/:id", authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { name, email, phone, company } = req.body;

  try {
    await db.query(
      "UPDATE customers SET name = ?, email = ?, phone = ?, company = ? WHERE id = ? AND user_id = ?",
      [name, email, phone, company, id, req.user.id]
    );
    res.send("Customer updated successfully");
  } catch (error) {
    console.error(error);
    res.status(500).send("Error updating customer");
  }
});

// Delete Customer
app.delete("/customers/:id", authenticateToken, async (req, res) => {
  const { id } = req.params;

  try {
    await db.query("DELETE FROM customers WHERE id = ? AND user_id = ?", [
      id,
      req.user.id,
    ]);
    res.send("Customer deleted successfully");
  } catch (error) {
    console.error(error);
    res.status(500).send("Error deleting customer");
  }
});

// Start server and initialize database
const startServer = async () => {
  await initializeDatabase();
  app.listen(process.env.PORT, () => {
    console.log(`Server running at http://localhost:${process.env.PORT}`);
  });
};

startServer();
