require("dotenv").config();
const bcrypt = require("bcrypt");
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");
const express = require("express");
const db = require("better-sqlite3")("ourApp.db");
db.pragma("journal_mode = WAL");
const app = express();

// db setup start
const createTable = db.transaction(() => {
  db.prepare(
    `
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL UNIQUE,
      password TEXT NOT NULL
    )
  `
  ).run();
});
createTable();
// db setup end

app.set("view engine", "ejs");
app.use(express.urlencoded({ extended: false }));
app.use(express.static("public"));
app.use(cookieParser());

//middlewARE
app.use(function (req, res, next) {
  res.locals.errors = [];

  // try to catch  and decode incoming request
  try {
    const decode = jwt.verify(req.cookies.ourSimpleApp, process.env.JWTSECRET);
    req.user = decode;
  } catch (err) {
    req.user = false;
  }
  res.locals.user = req.user;
  console.log(req.user);
  next();
});
app.get("/login", (req, res) => {
  res.render("login");
});
app.get("/", (req, res) => {
  // Check if req.user exists and has a userid property
  if (req.user && req.user.userid) {
    return res.render("dashboard");
  }
  res.render("homepage");
});
app.get("/logout", (req, res) => {
  res.clearCookie('ourSimpleApp')
  res.redirect("/");
});

app.post("/register", (req, res) => {
  const errors = [];
  if (typeof req.body.username !== "string") req.body.username = "";
  if (typeof req.body.password !== "string") req.body.password = "";

  req.body.username = req.body.username.trim();

  if (!req.body.username) errors.push("You must provide a user name ");
  if (req.body.username && req.body.username.length < 3)
    errors.push("A username should be more than three characters ");
  if (req.body.username && req.body.username.length > 10)
    errors.push("A username should not more than 10 characters ");
  if (req.body.username && !req.body.username.match(/^[a-zA-Z0-9]+$/))
    errors.push("A username can a only contain letters and numbers ");

  if (!req.body.password) errors.push("You must provide a user name ");
  if (req.body.password && req.body.password.length < 8)
    errors.push("A password should be more than three characters ");
  if (req.body.password && req.body.password.length > 15)
    errors.push("A password should not more than 10 characters ");

  if (errors.length) {
    return res.render("homepage", { errors });
  }
  //save the new user to the Db and log in the user by giving them the session cookie
  const salt = bcrypt.genSaltSync(10);
  req.body.password = bcrypt.hashSync(req.body.password, salt);

  const ourStatement = db.prepare(
    "INSERT INTO users (username, password) VALUES (?,?)"
  );
  const result = ourStatement.run(req.body.username, req.body.password);

  const lookupStatement = db.prepare("SELECT * FROM users WHERE ROWID = ?");
  const ourUser = lookupStatement.get(result.lastInsertRowid);
  //log the user in by giving a cookie
  const ourTokenValue = jwt.sign(
    {
      exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24,
      skyColor: "blue",
      userid: ourUser.id,
      username: ourUser.username,
    },
    process.env.JWTSECRET
  );

  res.cookie("ourSimpleApp", ourTokenValue, {
    httpOnly: true,
    secure: true,
    sameSite: "strict",
    maxAge: 1000 * 60 * 60 * 24,
  });
  //   res.send("thank you");
  res.redirect("/");
});
app.listen(3000);
