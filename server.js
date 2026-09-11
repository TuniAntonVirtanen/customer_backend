import express from "express";
import session from "express-session";

const app = express();

// Parse form submissions and JSON
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Set up browser sessions (Required for web login state)
app.use(
  session({
    secret: "mock-customer-secret-key",
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 60 } // 1 hour session
  })
);

// Hardcoded user credentials for testing
const MOCK_USER = {
  username: "user",
  password: "password"
};

// ===========================================================================
// 1. WEB APP ROUTES (For humans accessing in a browser)
// ===========================================================================

// Home Page: Displays login form or logged-in status
app.get("/", (req, res) => {
  if (req.session.isLoggedIn) {
    return res.send(`
      <div style="font-family: sans-serif; padding: 20px;">
        <h2>Welcome to Mock Customer Dashboard 🎉</h2>
        <p>Logged in as: <strong>${req.session.username}</strong></p>
        <form action="/logout" method="POST">
          <button type="submit" style="padding: 8px 16px;">Log Out</button>
        </form>
      </div>
    `);
  }

  res.send(`
    <div style="font-family: sans-serif; padding: 20px;">
      <h2>Mock Customer Login</h2>
      <form action="/login" method="POST" style="display: inline-block; text-align: left;">
        <div>
          <label>Username:</label><br>
          <input type="text" name="username" required style="padding: 5px;" />
        </div><br>
        <div>
          <label>Password:</label><br>
          <input type="password" name="password" required style="padding: 5px;" />
        </div><br>
        <button type="submit" style="padding: 8px 16px;">Log In</button>
      </form>
      <p><small>Use <code>user</code> / <code>password</code> to log in.</small></p>
    </div>
  `);
});

// Login POST Handler
app.post("/login", (req, res) => {
  const { username, password } = req.body;

  if (username === MOCK_USER.username && password === MOCK_USER.password) {
    req.session.isLoggedIn = true;
    req.session.username = username;

    // Check if user was sent here from an OAuth flow (e.g. from an LLM prompt)
    const redirectTo = req.session.returnTo || "/";
    delete req.session.returnTo;
    return res.redirect(redirectTo);
  }

  res.status(401).send(`
    <h3>Invalid Credentials ❌</h3>
    <a href="/">Try Again</a>
  `);
});

// Logout POST Handler
app.post("/logout", (req, res) => {
  req.session.destroy(() => {
    res.redirect("/");
  });
});

// ===========================================================================
// 2. OAUTH / MCP BRIDGE ENDPOINTS (What the LLM flow will hit)
// ===========================================================================

// OAuth Authorization Endpoint
// The LLM client pops open a browser window to this endpoint
app.get("/oauth/authorize", (req, res) => {
  const redirectUri = req.query.redirect_uri;

  // Step A: If user is NOT logged in, save where they were going and force login
  if (!req.session.isLoggedIn) {
    req.session.returnTo = req.originalUrl;
    return res.redirect("/");
  }

  // Step B: User IS logged in! Generate an authorization code
  const mockAuthCode = "auth_code_" + Math.random().toString(36).substring(2, 10);

  // If a redirect URI was provided (standard OAuth), send them back to the client
  if (redirectUri) {
    return res.redirect(`${redirectUri}?code=${mockAuthCode}`);
  }

  // Fallback for manual testing: Show the token/code on screen
  res.send(`
    <div style="font-family: sans-serif; padding: 20px;">
      <h3>Authorization Granted! ✅</h3>
      <p>Issued Authorization Code: <code>${mockAuthCode}</code></p>
    </div>
  `);
});

// Token Exchange Endpoint
// The MCP server calls this in the background to swap the authorization code for an Access Token
app.post("/oauth/token", (req, res) => {
  const { code } = req.body;

  if (code && code.startsWith("auth_code_")) {
    return res.json({
      access_token: "mock_access_token_9999",
      token_type: "Bearer",
      expires_in: 3600
    });
  }

  res.status(400).json({ error: "invalid_grant" });
});

// ===========================================================================
// SERVER START
// ===========================================================================
const port = process.env.PORT || 4000;
app.listen(port, () => {
  console.log(`Mock Customer Server running on http://localhost:${port}`);
});