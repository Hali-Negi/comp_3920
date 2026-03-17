const express = require("express");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const bcrypt = require("bcrypt");
const mysql = require("mysql2/promise");
require("dotenv").config();

const port = process.env.PORT || 3000;

const app = express();
app.use(express.urlencoded({ extended: true }));

const saltRounds = 12;
const expireTime = 60 * 60 * 1000; // expires in 1 hour

// MongoDB for sessions
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;
const node_session_secret = process.env.NODE_SESSION_SECRET;

// MySQL for users
const mysql_host = process.env.MYSQL_HOST;
const mysql_user = process.env.MYSQL_USER;
const mysql_password = process.env.MYSQL_PASSWORD;
const mysql_database = process.env.MYSQL_DATABASE;

// Create MySQL connection pool
const dbPool = mysql.createPool({
  host: mysql_host,
  user: mysql_user,
  password: mysql_password,
  database: mysql_database,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// MongoDB session store
var mongoStore = MongoStore.create({
  mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
  crypto: {
    secret: mongodb_session_secret
  }
});

app.set('view engine', 'ejs');

app.use(session({
  secret: node_session_secret,
  store: mongoStore,
  saveUninitialized: false,
  resave: false,
  cookie: { maxAge: expireTime }
}));

app.use(express.static(__dirname + '/public'));

// Middleware to check if user is logged in
function isAuthenticated(req, res, next) {
  if (req.session.authenticated) {
    next();
  } else {
    res.redirect("/");
  }
}

// Home page
app.get("/", (req, res) => {
  if (req.session.authenticated) {
    res.render("index", {
      heading: `Hello, ${req.session.username}!`,
      btn1: "Go to Members Area",
      btn2: "Logout",
      urls: ['/members', '/logout']
    });
  } else {
    res.render("index", {
      heading: "",
      btn1: "Sign Up",
      btn2: "Log In",
      urls: ['/signup', '/login']
    });
  }
});

// Signup page
app.get("/signup", (req, res) => {
  let error = req.query.error;
  let message = "";
  if (error === "username") {
    message = "Please provide a username.";
  } else if (error === "password") {
    message = "Please provide a password.";
  }
  res.render("signup", { error: message });
});

// Signup submit - UNSAFE: vulnerable to SQL injection
app.post("/signupSubmit", async (req, res) => {
  let username = req.body.username;
  let password = req.body.password;

  // Validate inputs
  if (!username || username.trim() === "") {
    res.redirect("/signup?error=username");
    return;
  }
  if (!password || password.trim() === "") {
    res.redirect("/signup?error=password");
    return;
  }

  // Hash the password
  let hashedPassword = await bcrypt.hash(password, saltRounds);

  // UNSAFE: SQL Injection vulnerability - directly concatenating user input
  let query = `INSERT INTO user (username, password) VALUES ('${username}', '${hashedPassword}')`;

  try {
    await dbPool.query(query);
    
    req.session.authenticated = true;
    req.session.username = username;
    req.session.cookie.maxAge = expireTime;
    
    res.redirect("/members");
  } catch (err) {
    console.log("Error: " + err);
    res.redirect("/signup");
  }
});

// Login page
app.get("/login", (req, res) => {
  let error = req.query.error;
  let message = "";
  if (error === "invalid") {
    message = "Username and password not found.";
  } else if (error === "username") {
    message = "Please provide a username.";
  } else if (error === "password") {
    message = "Please provide a password.";
  }
  res.render("login", { error: message });
});


// Login submit - UNSAFE: vulnerable to SQL injection (bypasses password check)
app.post("/loginSubmit", async (req, res) => {
  let username = req.body.username;
  let password = req.body.password;

  if (!username || username.trim() === "") {
    res.redirect("/login?error=username");
    return;
  }
  if (!password || password.trim() === "") {
    res.redirect("/login?error=password");
    return;
  }

  // UNSAFE: SQL injection vulnerability
  let query = `SELECT * FROM user WHERE username = '${username}'`;


  try {
    const [rows] = await dbPool.query(query);

    // UNSAFE: if ANY row comes back, log them in (this is intentionally bad)
    if (rows.length > 0) {
      req.session.authenticated = true;
      req.session.username = rows[0].username;
      req.session.cookie.maxAge = expireTime;
      res.redirect("/members");
      return;
    }

    res.redirect("/login?error=invalid");
  } catch (err) {
    console.log("Error: " + err);
    res.redirect("/login?error=invalid");
  }
});


// Members page - protected
app.get("/members", isAuthenticated, (req, res) => {
  const images = ['cat1.jpg', 'cat2.jpg', 'cat3.jpg'];
  const randomImage = images[Math.floor(Math.random() * images.length)];
  // NOTE: HTML injection vulnerability is controlled in members.ejs:
  // V1_Unsafe uses <%- username %> , V2_Safe uses <%= username %> 
  res.render("members", { 
    username: req.session.username,
    image: randomImage
  });
});

// Logout
app.get("/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.log(err);
    }
    res.redirect("/");
  });
});

// 404 catch-all
app.use((req, res) => {
  res.status(404);
  res.render("404");
});

app.listen(port, () => {
  console.log("Server running on port " + port);
});