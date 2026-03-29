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
  port: process.env.MYSQL_PORT ? Number(process.env.MYSQL_PORT) : 3306,
  ssl: { rejectUnauthorized: false },
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  namedPlaceholders: true
});

// MongoDB session store
var mongoStore = MongoStore.create({
  mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
  crypto: {
    secret: mongodb_session_secret
  }
});

app.set('view engine', 'ejs');

// Session config (cookie expires after 1 hour)
app.use(
  session({
    secret: node_session_secret,
    store: mongoStore,
    saveUninitialized: false,
    resave: false,
    cookie: {
      maxAge: expireTime
    }
  })
);

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
      btn1: "Go to Chats",
      btn2: "Logout",
      urls: ['/groups', '/logout']
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
  } else if (error === "weakpassword") {
    message = "Password must be at least 10 characters and include uppercase, lowercase, a number, and a symbol.";
  }
  res.render("signup", { error: message });
});

app.post("/signupSubmit", async (req, res) => {
  const username = req.body.username;
  const password = req.body.password;

  if (!username || username.trim() === "") {
    res.redirect("/signup?error=username");
    return;
  }
  if (!password || password.trim() === "") {
    res.redirect("/signup?error=password");
    return;
  }

  // Password validation
  const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{10,}$/;
  if (!passwordRegex.test(password)) {
    res.redirect("/signup?error=weakpassword");
    return;
  }

  try {
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    const query = "INSERT INTO user (username, password) VALUES (:username, :password)";
    await dbPool.execute(query, { username, password: hashedPassword });

    const [result] = await dbPool.execute("SELECT user_id FROM user WHERE username = :username", { username });

    req.session.authenticated = true;
    req.session.username = username;
    req.session.user_id = result[0].user_id;

    req.session.save((err) => {
      if (err) console.log("Session save error:", err);
      res.redirect("/groups");
    });
  } catch (err) {
    console.log("Signup error:", err);
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

// Login submit
app.post("/loginSubmit", async (req, res) => {
  const username = req.body.username;
  const password = req.body.password;

  if (!username || username.trim() === "") {
    res.redirect("/login?error=username");
    return;
  }
  if (!password || password.trim() === "") {
    res.redirect("/login?error=password");
    return;
  }

  try {
    const query = "SELECT * FROM user WHERE username = :username";
    const [rows] = await dbPool.execute(query, { username });

    if (rows.length === 0) {
      res.redirect("/login?error=invalid");
      return;
    }

    const match = await bcrypt.compare(password, rows[0].password);
    if (!match) {
      res.redirect("/login?error=invalid");
      return;
    }

    req.session.authenticated = true;
    req.session.username = rows[0].username;
    req.session.user_id = rows[0].user_id;

    req.session.save((err) => {
      if (err) console.log("Session save error:", err);
      res.redirect("/groups");
    });
  } catch (err) {
    console.log("Login error:", err);
    res.redirect("/login?error=invalid");
  }
});




// Groups page - protected
app.get("/groups", isAuthenticated, async (req, res) => {
  const user_id = req.session.user_id;

  // Get all groups with last message date and unread count
  const [groups] = await dbPool.execute(`
    SELECT r.room_id, r.name,
      MAX(m.sent_datetime) AS last_message_date,
      SUM(CASE WHEN m.message_id > (
        SELECT last_read_message_id FROM room_user 
        WHERE user_id = :user_id AND room_id = r.room_id
      ) THEN 1 ELSE 0 END) AS unread_count
    FROM room r
    JOIN room_user ru ON ru.room_id = r.room_id AND ru.user_id = :user_id
    LEFT JOIN room_user ru2 ON ru2.room_id = r.room_id
    LEFT JOIN message m ON m.room_user_id = ru2.room_user_id
    WHERE ru.user_id = :user_id
    GROUP BY r.room_id, r.name
    ORDER BY last_message_date DESC
  `, { user_id });

  res.render("groups", { username: req.session.username, groups });
});

// Create group page
app.get("/groups/create", isAuthenticated, async (req, res) => {
  const [users] = await dbPool.execute(
    "SELECT user_id, username FROM user WHERE user_id != :user_id",
    { user_id: req.session.user_id }
  );
  res.render("create_group", { username: req.session.username, users });
});

app.post("/groups/create", isAuthenticated, async (req, res) => {
  const group_name = req.body.group_name;
  const selected_users = req.body.selected_users || [];
  const user_id = req.session.user_id;

  if (!group_name || group_name.trim() === "") {
    res.redirect("/groups/create");
    return;
  }

  // Create the room
  const [result] = await dbPool.execute(
    "INSERT INTO room (name) VALUES (:name)",
    { name: group_name }
  );
  const room_id = result.insertId;

  // Add the creator to the room
  await dbPool.execute(
    "INSERT INTO room_user (user_id, room_id) VALUES (:user_id, :room_id)",
    { user_id, room_id }
  );

  // Add selected users to the room
  const usersToAdd = Array.isArray(selected_users) ? selected_users : [selected_users];
  for (const uid of usersToAdd) {
    await dbPool.execute(
      "INSERT INTO room_user (user_id, room_id) VALUES (:user_id, :room_id)",
      { user_id: uid, room_id }
    );
  }

  res.redirect("/groups");
});





// Invite people page
app.get("/groups/:room_id/invite", isAuthenticated, async (req, res) => {
  const room_id = req.params.room_id;
  const user_id = req.session.user_id;

  // Authorization check
  const [membership] = await dbPool.execute(
    "SELECT * FROM room_user WHERE user_id = :user_id AND room_id = :room_id",
    { user_id, room_id }
  );
  if (membership.length === 0) {
    res.status(400).send("Access denied.");
    return;
  }

  // Get current members
  const [members] = await dbPool.execute(`
    SELECT u.username FROM room_user ru
    JOIN user u ON ru.user_id = u.user_id
    WHERE ru.room_id = :room_id
  `, { room_id });

  // Get users NOT in the group
  const [nonMembers] = await dbPool.execute(`
    SELECT u.user_id, u.username FROM user u
    WHERE u.user_id NOT IN (
      SELECT ru.user_id FROM room_user ru WHERE ru.room_id = :room_id
    )
  `, { room_id });

  // Get room info
  const [rooms] = await dbPool.execute(
    "SELECT * FROM room WHERE room_id = :room_id",
    { room_id }
  );

  res.render("invite", {
    username: req.session.username,
    room: rooms[0],
    members,
    nonMembers,
    room_id
  });
});

// Add person to group
app.post("/groups/:room_id/invite", isAuthenticated, async (req, res) => {
  const room_id = req.params.room_id;
  const user_id = req.session.user_id;
  const invite_user_id = req.body.invite_user_id;

  // Authorization check
  const [membership] = await dbPool.execute(
    "SELECT * FROM room_user WHERE user_id = :user_id AND room_id = :room_id",
    { user_id, room_id }
  );
  if (membership.length === 0) {
    res.status(400).send("Access denied.");
    return;
  }

  await dbPool.execute(
    "INSERT INTO room_user (user_id, room_id) VALUES (:invite_user_id, :room_id)",
    { invite_user_id, room_id }
  );

  res.redirect("/groups/" + room_id + "/invite");
});






// Chat page - show messages in a group
app.get("/groups/:room_id", isAuthenticated, async (req, res) => {
  console.log("HIT chat route, room_id =", req.params.room_id);
  const room_id = req.params.room_id;
  const user_id = req.session.user_id;

  // Authorization check
  const [membership] = await dbPool.execute(
    "SELECT * FROM room_user WHERE user_id = :user_id AND room_id = :room_id",
    { user_id, room_id }
  );
  if (membership.length === 0) {
    res.status(400).send("Access denied.");
    return;
  }

  // Get room info
  const [rooms] = await dbPool.execute(
    "SELECT * FROM room WHERE room_id = :room_id",
    { room_id }
  );

  // Get messages
  const [messages] = await dbPool.execute(`
    SELECT m.message_id, m.text, m.sent_datetime, u.username
    FROM message m
    JOIN room_user ru ON m.room_user_id = ru.room_user_id
    JOIN user u ON ru.user_id = u.user_id
    WHERE ru.room_id = :room_id
    ORDER BY m.sent_datetime ASC
  `, { room_id });

  // Clear unread messages by updating last_read_message_id to the latest message
  // Save last read before clearing
  const lastReadMessageId = membership[0].last_read_message_id;
  if (messages.length > 0) {
    const lastMessageId = messages[messages.length - 1].message_id;
    await dbPool.execute(`
      UPDATE room_user SET last_read_message_id = :lastMessageId
      WHERE user_id = :user_id AND room_id = :room_id
    `, { lastMessageId, user_id, room_id });
  }

  // Get emoji reactions for each message
  const [reactions] = await dbPool.execute(`
    SELECT mr.message_id, e.emoji_id, e.symbol, COUNT(*) as count
    FROM message_reaction mr
    JOIN emoji e ON mr.emoji_id = e.emoji_id
    WHERE mr.message_id IN (
      SELECT m.message_id FROM message m
      JOIN room_user ru ON m.room_user_id = ru.room_user_id
      WHERE ru.room_id = :room_id
    )
    GROUP BY mr.message_id, e.emoji_id, e.symbol
  `, { room_id });

  // Get all emojis
  const [emojis] = await dbPool.execute("SELECT * FROM emoji");

  res.render("chat", {
    username: req.session.username,
    room: rooms[0],
    messages,
    reactions,
    emojis,
    user_id,
    lastReadMessageId
  });
});

// Send a message
app.post("/groups/:room_id/message", isAuthenticated, async (req, res) => {
  const room_id = req.params.room_id;
  const user_id = req.session.user_id;
  const text = req.body.text;

  // Authorization check
  const [membership] = await dbPool.execute(
    "SELECT * FROM room_user WHERE user_id = :user_id AND room_id = :room_id",
    { user_id, room_id }
  );
  if (membership.length === 0) {
    res.status(400).send("Access denied.");
    return;
  }

  const room_user_id = membership[0].room_user_id;

  await dbPool.execute(
    "INSERT INTO message (room_user_id, text) VALUES (:room_user_id, :text)",
    { room_user_id, text }
  );

  res.redirect("/groups/" + room_id);
});




// Add emoji reaction
app.post("/groups/:room_id/react", isAuthenticated, async (req, res) => {
  const room_id = req.params.room_id;
  const user_id = req.session.user_id;
  const message_id = req.body.message_id;
  const emoji_id = req.body.emoji_id;

  // Authorization check
  const [membership] = await dbPool.execute(
    "SELECT * FROM room_user WHERE user_id = :user_id AND room_id = :room_id",
    { user_id, room_id }
  );
  if (membership.length === 0) {
    res.status(400).send("Access denied.");
    return;
  }

  // Insert reaction (ignore if already reacted with same emoji)
  await dbPool.execute(
    `INSERT IGNORE INTO message_reaction (message_id, emoji_id, user_id) 
     VALUES (:message_id, :emoji_id, :user_id)`,
    { message_id, emoji_id, user_id }
  );

  res.redirect("/groups/" + room_id);
});




// Logout
app.get("/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) console.log(err);
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