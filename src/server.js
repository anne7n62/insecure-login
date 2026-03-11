import express from "express";
import session from "express-session";
import rateLimit from "express-rate-limit";
import { z } from "zod";
import { init, get, run, all, verifyPassword } from "./db.js";

const app = express();
const PORT = process.env.PORT ?? 3000;

await init();

app.use(express.static("public"));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

//Begrænsninger for login-forsøg (undgå brute-force)
//Confidentiality: forhindre at gætte login og få adgang til private data
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 3,
  standardHeaders: true,
  legacyHeaders: false,
});

// Validering af input data ved hjælp af Zod
//Integrity: Sikre data har korrekt format og type, forhindre SQL-injection
// Confidentiality: forhindre at angriber kan indsætte skadelig SQL-kode og få adgang til private data
const loginSchema = z.object({
  email: z.string().email().max(254),
  password: z.string().min(8).max(128),
});

const validate = (schema) => (req, res, next) => {
  const result = schema.safeParse(req.body);

  if (!result.success) {
    return res.status(400).json({ message: "Invalid input" });
  }

  //Istedet for req.body - returnere de felter som er valideret og sikre at de har korrekt format og type
  //Ellers kan man f.eks. ændre sin rolle til admin
  req.validatedData = result.data;
  next();
};

//Session
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: true, //https:true
      sameSite: "lax",
      maxAge: 1000 * 60 * 60, // 1 time
    },
  }),
);

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

//Vis brugere
app.get("/debug/users", async (req, res) => {
  const users = await all("SELECT id, email, password, role FROM users");
  res.json(users);
});

// browser -> server: email + password

app.post("/login", loginLimiter, validate(loginSchema), async (req, res) => {
  const { email, password } = req.validatedData;

  // Hent bruger fra databasen
  const user = await get(
    `SELECT id, email, password, role FROM users WHERE email=?`,
    [email],
  );
  if (!user) return res.status(404).json({ message: "User not found" });

  // Sammenlign det indtastede password med det hash'ede password
  const valid = await verifyPassword(password, user.password);
  if (!valid) return res.status(401).json({ message: "Wrong password" });

  // Regenerer session for at beskytte mod session fixation
  req.session.regenerate((err) => {
    if (err) return res.status(500).json({ message: "Session error" });

    // Sæt brugerdata i den nye session
    req.session.user = { id: user.id, email: user.email, role: user.role };

    res.json({ message: "Logged in", user: req.session.user });
  });
});

app.post("/logout", (req, res) => {
  req.session.destroy(() => res.json({ message: "Logged out" }));
});

app.get("/me", requireAuth, (req, res) => {
  res.json({ user: req.session.user });
});

// Update profile schema
const profileSchema = z.object({
  email: z.string().email().max(254),
  role: z.enum(["user", "admin"]),
});

app.post(
  "/profile/update",
  requireAuth,
  validate(profileSchema),
  async (req, res) => {
    const { email, role } = req.validatedData;

    await run(`UPDATE users SET email=?, role=? WHERE id=?`, [
      email,
      role,
      req.session.user.id,
    ]);
    res.json({ message: "Profile updated" });
  },
);

app.listen(PORT, () => {
  console.log(`http://localhost:${PORT}`);
});
