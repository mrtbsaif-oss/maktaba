# 📚 Maktaba — Setup Guide

## What you'll need
- A computer (Windows, Mac, or Linux)
- Internet connection (for the first install only)

---

## Step 1 — Install Node.js

Node.js is the engine that runs your server.

1. Go to: https://nodejs.org
2. Click the big green **"LTS"** button to download
3. Open the downloaded file and follow the installer (just click Next → Next → Install)
4. When done, open a **Terminal** (Mac/Linux) or **Command Prompt** (Windows)
5. Type this and press Enter to confirm it worked:
   ```
   node --version
   ```
   You should see something like: `v20.11.0`

---

## Step 2 — Put the project folder somewhere easy

Move the `maktaba` folder to somewhere easy to find, like your Desktop.

Example path: `C:\Users\YourName\Desktop\maktaba`

---

## Step 3 — Open the project in Terminal / Command Prompt

**On Windows:**
1. Open the `maktaba` folder
2. Hold **Shift** and right-click inside the folder
3. Click **"Open PowerShell window here"** or **"Open Command Prompt here"**

**On Mac:**
1. Open Terminal (search "Terminal" in Spotlight)
2. Type `cd ` (with a space), then drag the `maktaba` folder into the Terminal window
3. Press Enter

---

## Step 4 — Install the dependencies

In the Terminal, type this and press Enter:

```
npm install
```

This downloads all the libraries the server needs. It takes about 30 seconds.
You'll see a lot of text — that's normal!

---

## Step 5 — Start the server

Type this and press Enter:

```
node server.js
```

You should see:
```
✅ Default admin created: admin@library.com / admin123
📚 Maktaba server running!
👉 Open your browser: http://localhost:3000
```

---

## Step 6 — Open your library in the browser

Open any browser (Chrome, Firefox, Edge) and go to:

**http://localhost:3000**

Your library is running! 🎉

---

## How to use it

### As a visitor
- Browse books on the main page
- Click **Read** to open a PDF in the browser
- Click **⬇** to download the PDF

### As admin
1. Click **Sign In** in the top right
2. Email: `admin@library.com`
3. Password: `admin123`
4. You'll see the ⚙ Admin button — click it
5. Add a book: fill in the title, author, genre, and upload a PDF
6. Click **Save Book** — it appears in the library instantly!

---

## How to stop the server

Go back to the Terminal and press **Ctrl + C**

## How to start it again next time

Open the Terminal in the maktaba folder and run:
```
node server.js
```

---

## Where is my data saved?

- **Books info** (title, author, etc.) → saved in `maktaba.db` (a database file in the folder)
- **PDF files** → saved in the `uploads/` folder
- Both survive restarts — your books are permanently stored! ✅

---

## Changing the admin password

Open `server.js` in any text editor, find this line near the top:

```js
db.prepare('INSERT INTO admins (email, password) VALUES (?, ?)').run('admin@library.com', 'admin123');
```

Change `admin123` to your password, save, and restart the server.
*(Note: only applies on first run. If the DB already exists, delete `maktaba.db` first.)*

---

## Something not working?

| Problem | Solution |
|---------|----------|
| `node: command not found` | Node.js isn't installed — go back to Step 1 |
| `Cannot find module` | Run `npm install` again |
| Page shows "Cannot connect" | Make sure the server is running (`node server.js`) |
| Port 3000 already in use | Change `const PORT = 3000` to `3001` in server.js |
