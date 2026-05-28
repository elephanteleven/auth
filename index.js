const express = require('express');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const session = require('express-session');

const app = express();
const PORT = 3000;
const redirectToRoot = (req, res) => {
    res.redirect("/");
};

app.set('trust proxy', 1); 
app.use(session({
    secret: process.env.SESSION_SECRET || 'fallback-secret-key',
    resave: false,
    saveUninitialized: false, // Changed to false to avoid empty sessions
    cookie: {
        secure: false,        // Set to true if you set up HTTPS on Nginx later
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000 // 1 day
    }
}));
app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((user, done) => done(null, user));
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: `${process.env.WEB_URL}/auth/google/callback`,
},
(accessToken, refreshToken, profile, done) => {
    return done(null, profile);
}));

app.get("/auth", (req, res) => {
    if (!req.isAuthenticated()) {
        res.status(401).json({ authenticated: false, error: "Unauthorized" });
        return;
    }
    res.status(200).json({ authenticated: true, user: req.user });
});
app.get("/auth/google",
    passport.authenticate("google", { scope: ["profile", "email"] }));
app.get("/auth/google/callback",
    passport.authenticate("google", { failureRedirect: "/login" }),
    async (req, res) => {
        try {
            const token = (await (await fetch(`${process.env.BACKEND_URL}/auth/oauth`, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    email: req.user.emails[0].value,
                    providerId: req.user.id,
                    type: req.user.provider
                })
            })).json()).token;
            res.cookie(process.env.AUTH_COOKIE, token, {
                httpOnly: true,
                sameSite: 'lax',
                path: '/',
                maxAge: 60 * 60 * 24 * 7 * 1000 // Express maxAge is in milliseconds
            });
            redirectToRoot(req, res);
        } catch (error) {
            console.error(error);
            res.redirect("/auth/logout");
        }
    },
);
app.get("/auth/logout", (req, res) => {
    req.logout((err) => {
        if (err) {
            redirectToRoot(req, res);
            return;
        }
        req.session.destroy(() => {
            redirectToRoot(req, res);
        });
    });
});

app.listen(PORT, () => console.log(`Backend running internally on port ${PORT}`));
