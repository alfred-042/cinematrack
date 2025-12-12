require("dotenv").config();
const express = require("express");
const session = require("express-session");
const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const path = require("path");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const methodOverride = require("method-override");
const fetch = require("node-fetch"); // OMDb fetch

const Movie = require("./models/movie");
const User = require("./models/User");

const app = express();

const DEFAULT_POSTER = "/images/default-poster.png"; // buat file ini di public/images/

/* --------------------
   MONGO DB CONNECT
-------------------- */
async function connectDB() {
    try {
        await mongoose.connect(process.env.MONGO_URI);
        console.log("✅ MongoDB Atlas connected");
    } catch (err) {
        console.error("❌ MongoDB connection error:", err);
        process.exit(1);
    }
}
connectDB();

/* --------------------
   MIDDLEWARE
-------------------- */
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));
app.use(methodOverride("_method"));

app.use(
    session({
        secret: process.env.SESSION_SECRET || "secret",
        resave: false,
        saveUninitialized: false
    })
);

/* --------------------
   PASSPORT
-------------------- */
app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
    const user = await User.findById(id);
    done(null, user);
});

passport.use(
    new GoogleStrategy(
        {
            clientID: process.env.GOOGLE_CLIENT_ID,
            clientSecret: process.env.GOOGLE_CLIENT_SECRET,
            callbackURL: "/auth/google/callback"
        },
        async (accessToken, refreshToken, profile, done) => {
            let user = await User.findOne({ googleId: profile.id });

            if (!user) {
                user = await User.create({
                    googleId: profile.id,
                    email: profile.emails[0].value,
                    name: profile.displayName
                });
            }

            return done(null, user);
        }
    )
);

/* --------------------
   VIEW ENGINE
-------------------- */
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

/* --------------------
   ROUTES
-------------------- */
app.get("/", (req, res) => res.redirect("/login"));
app.get("/login", (req, res) => res.render("login"));
app.get("/register", (req, res) => res.render("register"));

/* --------------------
   LOCAL REGISTER
-------------------- */
app.post("/auth/local-register", async (req, res) => {
    const { email, password } = req.body;

    const exist = await User.findOne({ email });
    if (exist) return res.status(400).send("Email sudah digunakan!");

    const hashed = await bcrypt.hash(password, 10);

    await User.create({
        email,
        password: hashed,
        name: email.split("@")[0]
    });

    res.redirect("/login");
});

/* --------------------
   LOCAL LOGIN
-------------------- */
app.post("/auth/local-login", async (req, res) => {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user) return res.status(400).send("Email tidak ditemukan!");

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) return res.status(400).send("Password salah!");

    req.session.user = {
        id: user._id,
        email: user.email,
        name: user.name
    };

    res.redirect("/dashboard");
});

/* --------------------
   GOOGLE LOGIN
-------------------- */
app.get("/auth/google",
    passport.authenticate("google", { scope: ["profile", "email"] })
);

app.get(
    "/auth/google/callback",
    passport.authenticate("google", { failureRedirect: "/login" }),
    (req, res) => res.redirect("/dashboard")
);

/* --------------------
   MIDDLEWARE PROTECT
-------------------- */
function ensureLogin(req, res, next) {
    if (req.isAuthenticated() || req.session.user) return next();
    return res.redirect("/login");
}

/* --------------------
   DASHBOARD
-------------------- */
app.get("/dashboard", ensureLogin, async (req, res) => {
    const userId = req.user ? req.user._id : req.session.user.id;
    const movies = await Movie.find({ userId });

    const username = req.user ? req.user.name : req.session.user.name;

    res.render("dashboard", { username, movies });
});

/* --------------------
   LOGOUT
-------------------- */
app.get("/logout", (req, res) => {
    req.session.destroy(() => {
        req.logout(() => {});
        res.redirect("/login");
    });
});

/* --------------------
   MOVIE CRUD (WITH OMDB POSTER)
-------------------- */

// CREATE MOVIE + poster otomatis
app.post("/movies", ensureLogin, async (req, res) => {
    try {
        const userId = req.user ? req.user._id : req.session.user.id;
        const { title, category } = req.body;

        let poster = DEFAULT_POSTER;

        if (process.env.OMDB_KEY && title) {
            try {
                const api = `https://www.omdbapi.com/?t=${encodeURIComponent(title)}&apikey=${process.env.OMDB_KEY}`;
                const r = await fetch(api);
                const data = await r.json();

                if (data && data.Poster && data.Poster !== "N/A") {
                    poster = data.Poster;
                }
            } catch (err) {
                console.warn("OMDb fetch failed:", err);
            }
        }

        const movie = await Movie.create({
            userId,
            title,
            category,
            poster
        });

        res.json(movie);
    } catch (err) {
        console.error(err);
        res.status(500).send("Failed to create movie");
    }
});

// UPDATE MOVIE + update poster jika judul berubah
app.put("/movies/:id", ensureLogin, async (req, res) => {
    try {
        const userId = req.user ? req.user._id : req.session.user.id;
        const { title, category } = req.body;

        let update = { category };
        if (title) update.title = title;

        if (process.env.OMDB_KEY && title) {
            try {
                const api = `https://www.omdbapi.com/?t=${encodeURIComponent(title)}&apikey=${process.env.OMDB_KEY}`;
                const r = await fetch(api);
                const data = await r.json();

                if (data && data.Poster && data.Poster !== "N/A") {
                    update.poster = data.Poster;
                }
            } catch (err) {
                console.warn("OMDb fetch failed on update:", err);
            }
        }

        const movie = await Movie.findOneAndUpdate(
            { _id: req.params.id, userId },
            update,
            { new: true }
        );

        if (!movie) return res.status(404).send("Movie not found");

        res.json(movie);
    } catch (err) {
        console.error(err);
        res.status(500).send("Failed to update movie");
    }
});

// DELETE
app.delete("/movies/:id", ensureLogin, async (req, res) => {
    const userId = req.user ? req.user._id : req.session.user.id;
    await Movie.findOneAndDelete({ _id: req.params.id, userId });
    res.json({ success: true });
});

/* --------------------
   PROFILE PAGES
-------------------- */
app.get("/profile", ensureLogin, async (req, res) => {
    const userId = req.user ? req.user._id : req.session.user.id;
    const user = await User.findById(userId);

    res.render("profile", {
        user,
        message: null,
        messageType: null
    });
});

app.post("/profile/update", ensureLogin, async (req, res) => {
    try {
        const { name, email, currentPassword, newPassword } = req.body;

        const userId = req.user ? req.user._id : req.session.user.id;
        const user = await User.findById(userId);

        if (!user) return res.redirect("/login");

        if (name) user.name = name.trim();

        if (!user.googleId && email !== user.email) {
            const exists = await User.findOne({ email });
            if (exists) {
                return res.render("profile", {
                    user,
                    message: "Email sudah digunakan!",
                    messageType: "error"
                });
            }
            user.email = email;
        }

        if (!user.googleId && newPassword) {
            const valid = await bcrypt.compare(currentPassword, user.password);
            if (!valid) {
                return res.render("profile", {
                    user,
                    message: "Current password salah!",
                    messageType: "error"
                });
            }
            user.password = await bcrypt.hash(newPassword, 10);
        }

        await user.save();

        if (req.session.user) {
            req.session.user.name = user.name;
            req.session.user.email = user.email;
        }

        res.render("profile", {
            user,
            message: "Profile berhasil diperbarui!",
            messageType: "success"
        });

    } catch (err) {
        console.error(err);
        res.render("profile", {
            user,
            message: "Terjadi error.",
            messageType: "error"
        });
    }
});

/* --------------------
   START SERVER
-------------------- */
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
