
---

# Express + EJS + SQLite App 🚀

A simple backend project I’m building while learning **Node.js, Express, and databases**.
The goal is to understand how to structure a backend app, validate form inputs, and save users into a database.

---

## 🔧 Tech Stack

* **Node.js** – server runtime
* **Express.js** – web framework
* **EJS** – template engine for rendering views
* **SQLite (better-sqlite3)** – database for storing users
* **Nodemon** – auto-restart server during development

---

## ✨ Features (so far)

* Serve dynamic pages with EJS
* Basic form handling with POST requests
* Input validation (username & password rules)
* Error handling for invalid submissions
* SQLite database setup (using `better-sqlite3`)

---

## 🚀 Getting Started

### 1. Clone the repo

```bash
git clone https://github.com/your-username/your-repo-name.git
cd your-repo-name
```

### 2. Install dependencies

```bash
npm install
```

### 3. Run the app

```bash
nodemon server.js
```

Your app should now be running at:
👉 [http://localhost:3000](http://localhost:3000)

---

## 📂 Project Structure

```
.
├── public/           # static files (CSS, JS, images)
├── views/            # EJS templates (homepage.ejs, login.ejs, etc.)
├── server.js         # main server file
└── ourApp.db         # SQLite database file
```

---

## ✅ Validation Rules

* **Username**

  * Required
  * 3–10 characters
  * Only letters & numbers

* **Password**

  * Required
  * 8–15 characters

---

## 📌 Next Steps

* [ ] Add session cookies for login
* [ ] Hash passwords before saving
* [ ] Create user dashboard after login
* [ ] Add logout functionality

---

## 🧑‍💻 Author

Learning backend step by step ✨
Feel free to fork, open issues, or suggest improvements!

---

