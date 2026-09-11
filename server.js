import express from "express";
import session from "express-session";

const app = express();

app.set("trust proxy", 1);

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Global Request Logger
app.use((req, res, next) => {
  console.log(`[BACKEND REQ] ${req.method} ${req.url}`);
  next();
});

app.use(
  session({
    secret: "mock-customer-secret-key",
    resave: false,
    saveUninitialized: false,
    cookie: { 
      maxAge: 3600000, 
      secure: true,        
      sameSite: "none"     
    }
  })
);

const MOCK_USER = {
  username: "user",
  password: "password"
};

// ===========================================================================
// 1. WEB APP ROUTES
// ===========================================================================

app.get("/.well-known/oauth-authorization-server", (req, res) => {
  const hostUrl = `${req.protocol}://${req.get("host")}`;
  res.json({
    issuer: hostUrl,
    authorization_endpoint: `${hostUrl}/oauth/authorize`,
    token_endpoint: `${hostUrl}/oauth/token`,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code"],
    code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: ["none", "client_secret_post", "client_secret_basic"],
    scopes_supported: ["read", "write"]
  });
});

// Also alias OpenID discovery since ChatGPT tried fetching it in logs
app.get("/.well-known/openid-configuration", (req, res) => {
  res.redirect("/.well-known/oauth-authorization-server");
});

app.get("/", (req, res) => {
  console.log(`[BACKEND ROOT] Session ID: ${req.sessionID}, LoggedIn: ${!!req.session?.isLoggedIn}`);
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

app.post("/login", (req, res) => {
  const { username, password } = req.body;
  console.log(`[BACKEND LOGIN] Attempt for username: "${username}"`);

  if (username === MOCK_USER.username && password === MOCK_USER.password) {
    req.session.isLoggedIn = true;
    req.session.username = username;

    const redirectTo = req.session.returnTo || "/";
    console.log(`[BACKEND LOGIN SUCCESS] Redirecting to: ${redirectTo}`);
    delete req.session.returnTo;
    
    return req.session.save((err) => {
      if (err) console.error(`[BACKEND LOGIN ERROR] Session save failed:`, err);
      res.redirect(redirectTo);
    });
  }

  console.warn(`[BACKEND LOGIN FAILED] Invalid credentials for: "${username}"`);
  res.status(401).send(`
    <h3>Invalid Credentials ❌</h3>
    <a href="/">Try Again</a>
  `);
});

app.post("/logout", (req, res) => {
  console.log(`[BACKEND LOGOUT] User logged out.`);
  req.session.destroy(() => {
    res.redirect("/");
  });
});

// ===========================================================================
// 2. OAUTH / MCP BRIDGE ENDPOINTS
// ===========================================================================

app.get("/oauth/authorize", (req, res) => {
  const { redirect_uri, state, code_challenge, client_id } = req.query;
  console.log(`[BACKEND AUTHORIZE] Received Auth Request:`, {
    client_id,
    redirect_uri,
    state,
    code_challenge,
    isLoggedIn: !!req.session?.isLoggedIn
  });

  if (!req.session || !req.session.isLoggedIn) {
    console.log(`[BACKEND AUTHORIZE] Unauthenticated. Storing returnTo: ${req.originalUrl}`);
    req.session.returnTo = req.originalUrl; 
    return req.session.save((err) => {
      if (err) console.error(`[BACKEND AUTHORIZE ERROR] Session save failed:`, err);
      res.redirect("/");
    });
  }

  const mockAuthCode = "auth_code_" + Math.random().toString(36).substring(2, 10);
  console.log(`[BACKEND AUTHORIZE SUCCESS] Generated code: ${mockAuthCode}`);

  if (redirect_uri) {
    const redirectUrl = new URL(redirect_uri);
    redirectUrl.searchParams.set("code", mockAuthCode);
    if (state) redirectUrl.searchParams.set("state", state);
    
    // Explicitly send issuer back to pass RFC 9207 validation
    const hostUrl = `${req.protocol}://${req.get("host")}`;
    redirectUrl.searchParams.set("iss", hostUrl);
    
    const finalRedirect = redirectUrl.toString();
    return res.redirect(finalRedirect);
  }

  res.send(`Authorization Granted! Code: ${mockAuthCode}`);
});

app.post("/oauth/token", express.urlencoded({ extended: true }), (req, res) => {
  console.log("[BACKEND TOKEN REQ BODY]:", req.body);
  const { code, grant_type } = req.body;

  if (grant_type === "authorization_code" && code) {
    console.log("[BACKEND TOKEN SUCCESS] Issuing bearer token.");
    return res.json({
      access_token: "mock_access_token_9999",
      token_type: "Bearer",
      expires_in: 3600
    });
  }
  console.warn(`[BACKEND TOKEN REJECTED] Invalid code or grant_type. Code: "${code}", Grant: "${grant_type}"`);
  res.status(400).json({ error: "invalid_grant" });
});
  


const port = process.env.PORT || 4000;
app.listen(port, () => {
  console.log(`Mock Customer Server running on http://localhost:${port}`);
});