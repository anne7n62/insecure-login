import express from "express";
import session from "express-session";
import { init, get, run, all } from "./db.js";
import rateLimit from "express-rate-limit";

const app = express();
const PORT = process.env.PORT ?? 3000;

await init();

app.use(express.static("public"));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Rate limiting (Availability + brute force-beskyttelse)
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
});

const loginSchema = z.object({
  email: z.string().email().max(254),
  password: z.string().min(8).max(128),
});

// Middleware til validering
const validate = (schema) => (req, res, next) => {
  const result = schema.safeParse(req.body);

  if (!result.success) {
    return res.status(400).json({ message: "Invalid input" });
  }

  // Whitelisting: kun validerede felter videre
  req.validatedData = result.data;
  next();
};

app.post("/login", loginLimiter, validate(loginSchema), async (req, res) => {
  const { email, password } = req.validatedData;

  // Database lookup her (med parameterized query!)
  res.json({ message: "Login logic continues..." });
});

app.use(
  session({
    secret: "dev-secret",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: true,
      sameSite: "lax",
      maxAge: 1000 * 60 * 60, // 1 hour
    },
  }),
); // Rate limiting (Availability + brute force-beskyttelse)
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
});

const loginSchema = z.object({
  email: z.string().email().max(254),
  password: z.string().min(8).max(128),
});

const requireAuth = (req, res, next) => {
  if (!req.session.user) return res.status(401).send("Not logged in");
  next();
};

app.get("/", (req, res) => {
  res.send(`
    <h1>Insecure Login Lab</h1>
    <ul>
      <li><a href="/index.html">Login</a></li>
      <li><a href="/profile.html">Profile</a> (requires login)</li>
      <li><a href="/debug/users">Debug: users</a></li>
    </ul>
  `);
});

app.get("/debug/users", async (req, res) => {
  const users = await all("SELECT id, email, password, role FROM users");
  res.json(users);
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  const user = await get(`
    SELECT id, email, password, role
    FROM users
    WHERE email = '${email}'
  `);

  if (!user) return res.status(404).json({ message: "User not found" });

  if (password !== user.password) {
    return res.status(401).json({ message: "Wrong password" });
  }

  req.session.user = { id: user.id, email: user.email, role: user.role };

  res.json({ message: "Logged in", user: req.session.user });
});

app.post("/logout", (req, res) => {
  req.session.destroy(() => res.json({ message: "Logged out" }));
});

app.get("/me", requireAuth, (req, res) => {
  res.json({ user: req.session.user });
});

app.post("/profile/update", requireAuth, async (req, res) => {
  const { email, role } = req.body;

  await run(`
    UPDATE users
    SET email='${email}', role='${role}'
    WHERE id=${req.session.user.id}
  `);

  res.json({ message: "Profile updated" });
});

app.listen(PORT, () => {
  console.log(`http://localhost:${PORT}`);
});
