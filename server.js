import express from "express";
import session from "express-session";
import crypto from "crypto";
import jwt from "jsonwebtoken";

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

const MOCK_DATA = {
  workspace1: { completedTasks: 12, inProgressTasks: 3 },
  workspace2: { A: 5, B: 7, C: 3 },
  workspace3: [["D", "A"], ["A", "C"], ["B", "C"], ["D", "C"]]
};

// ===========================================================================
// OAUTH IN-MEMORY STORES (PROTOTYPE SIMULATION)
// PROD NOTE: Replace these Map() instances with PostgreSQL/Redis.
// ===========================================================================
const registeredClients = new Map(); // client_id -> client metadata
const authorizationCodes = new Map(); // code -> auth state (code_challenge, userId, etc.)

// ===========================================================================
// CRYPTOGRAPHIC KEYS (RS256)
// PROD NOTE: Load persistent RSA keys from environment secrets or AWS KMS.
// ===========================================================================
const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
  modulusLength: 2048,
  publicKeyEncoding: { type: "spki", format: "pem" },
  privateKeyEncoding: { type: "pkcs8", format: "pem" }
});

// Export key details for JWKS
const keyObject = crypto.createPublicKey(publicKey);
const jwk = keyObject.export({ format: "jwk" });
jwk.use = "sig";
jwk.alg = "RS256";
jwk.kid = "prototype-key-1";

// ===========================================================================
// 1. WEB APP & DISCOVERY ROUTES
// ===========================================================================

// JWKS Endpoint so MCP Backend can fetch public keys dynamically
app.get("/.well-known/jwks.json", (req, res) => {
  res.json({ keys: [jwk] });
});

app.get("/.well-known/oauth-authorization-server", (req, res) => {
  const hostUrl = `${req.protocol}://${req.get("host")}`;
  res.json({
    issuer: hostUrl,
    authorization_endpoint: `${hostUrl}/oauth/authorize`,
    token_endpoint: `${hostUrl}/oauth/token`,
    registration_endpoint: `${hostUrl}/oauth/register`,
    jwks_uri: `${hostUrl}/.well-known/jwks.json`,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code"],
    code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: ["none"],
    scopes_supported: ["read", "write"]
  });
});

app.get("/.well-known/openid-configuration", (req, res) => {
  res.redirect("/.well-known/oauth-authorization-server");
});

app.get("/", (req, res) => {
  if (req.session.isLoggedIn) {
    return res.send(`
      <div style="font-family: sans-serif; padding: 20px;">
        <h2>Welcome to Customer Dashboard 🎉</h2>
        <p>Logged in as: <strong>${req.session.username}</strong></p>
        <form action="/logout" method="POST">
          <button type="submit">Log Out</button>
        </form>
      </div>
    `);
  }

  res.send(`
    <div style="font-family: sans-serif; padding: 20px;">
      <h2>Mock Customer Login</h2>
      <form action="/login" method="POST">
        <label>Username:</label> <input type="text" name="username" required /><br><br>
        <label>Password:</label> <input type="password" name="password" required /><br><br>
        <button type="submit">Log In</button>
      </form>
      <p><small>Use <code>user</code> / <code>password</code></small></p>
    </div>
  `);
});

app.post("/login", (req, res) => {
  const { username, password } = req.body;
  if (username === MOCK_USER.username && password === MOCK_USER.password) {
    req.session.isLoggedIn = true;
    req.session.username = username;

    const redirectTo = req.session.returnTo || "/";
    delete req.session.returnTo;

    return req.session.save((err) => {
      if (err) console.error(`[BACKEND LOGIN ERROR]`, err);
      res.redirect(redirectTo);
    });
  }
  res.status(401).send("Invalid Credentials");
});

app.post("/logout", (req, res) => {
  req.session.destroy(() => res.redirect("/"));
});

// ===========================================================================
// 2. DATA API (CONSUMED BY MCP BACKEND)
// ===========================================================================

app.get("/api/data", (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ error: "unauthorized" });
  }

  const token = authHeader.split(" ")[1];
  try {
    // PROD NOTE: For internal calls, verify signed JWT directly
    const decoded = jwt.verify(token, publicKey, { algorithms: ["RS256"] });
    res.json(MOCK_DATA);
  } catch (err) {
    return res.status(403).json({ error: "invalid_token", message: err.message });
  }
});

// ===========================================================================
// 3. OAUTH 2.1 ENDPOINTS
// ===========================================================================

// Dynamic Client Registration (RFC 7591)
app.post("/oauth/register", (req, res) => {
  const { redirect_uris } = req.body;
  const clientId = "client_" + crypto.randomBytes(8).toString("hex");

  const clientMetadata = {
    client_id: clientId,
    client_id_issued_at: Math.floor(Date.now() / 1000),
    redirect_uris: redirect_uris || [],
    grant_types: ["authorization_code"],
    response_types: ["code"],
    token_endpoint_auth_method: "none" // Public Client (PKCE required)
  };

  registeredClients.set(clientId, clientMetadata);
  res.status(201).json(clientMetadata);
});

// Authorization Endpoint with PKCE
app.get("/oauth/authorize", (req, res) => {
  const { client_id, redirect_uri, state, code_challenge, code_challenge_method } = req.query;

  // 1. Force Login First
  if (!req.session || !req.session.isLoggedIn) {
    req.session.returnTo = req.originalUrl;
    return req.session.save(() => res.redirect("/"));
  }

  // 2. Strict PKCE Verification Check
  if (!code_challenge || code_challenge_method !== "S256") {
    return res.status(400).send("OAuth 2.1 requires PKCE with S256 code_challenge_method.");
  }

  // PROD NOTE: Validate redirect_uri matches client's registered redirect_uris here.

  // 3. Issue Authorization Code
  const mockAuthCode = "code_" + crypto.randomBytes(16).toString("hex");
  authorizationCodes.set(mockAuthCode, {
    clientId: client_id,
    redirectUri: redirect_uri,
    codeChallenge: code_challenge,
    username: req.session.username,
    expiresAt: Date.now() + 10 * 60 * 1000 // 10 minutes
  });

  // 4. Redirect Back to Client
  if (redirect_uri) {
    const redirectUrl = new URL(redirect_uri);
    redirectUrl.searchParams.set("code", mockAuthCode);
    if (state) redirectUrl.searchParams.set("state", state);
    redirectUrl.searchParams.set("iss", `${req.protocol}://${req.get("host")}`);
    return res.redirect(redirectUrl.toString());
  }

  res.send(`Authorization Granted! Code: ${mockAuthCode}`);
});

// Token Endpoint (PKCE Verification & Signed JWT Issue)
app.post("/oauth/token", express.urlencoded({ extended: true }), (req, res) => {
  const { code, grant_type, code_verifier, client_id } = req.body;

  if (grant_type !== "authorization_code" || !code || !code_verifier) {
    return res.status(400).json({ error: "invalid_request", error_description: "Missing code or code_verifier" });
  }

  const authData = authorizationCodes.get(code);
  if (!authData || Date.now() > authData.expiresAt) {
    authorizationCodes.delete(code);
    return res.status(400).json({ error: "invalid_grant", error_description: "Code invalid or expired" });
  }

  // PROD NOTE: Ensure code single-use lifetime
  authorizationCodes.delete(code);

  // Validate PKCE (Base64URL(SHA256(code_verifier)) == code_challenge)
  const calculatedChallenge = crypto
    .createHash("sha256")
    .update(code_verifier)
    .digest("base64url");

  if (calculatedChallenge !== authData.codeChallenge) {
    return res.status(400).json({ error: "invalid_grant", error_description: "PKCE verification failed" });
  }

  // Issue Signed RS256 JWT
  const hostUrl = `${req.protocol}://${req.get("host")}`;
  const accessToken = jwt.sign(
    {
      sub: authData.username,
      client_id: client_id || authData.clientId,
      scope: "read write"
    },
    privateKey,
    {
      algorithm: "RS256",
      expiresIn: "1h",
      issuer: hostUrl,
      keyid: "prototype-key-1"
    }
  );

  res.json({
    access_token: accessToken,
    token_type: "Bearer",
    expires_in: 3600,
    scope: "read write"
  });
});

const port = process.env.PORT || 4000;
app.listen(port, () => {
  console.log(`Customer Server running on http://localhost:${port}`);
});