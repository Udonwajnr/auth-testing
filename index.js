const express = require('express');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const jwt = require('jsonwebtoken');
const cookieSession = require('cookie-session');
const dotenv = require('dotenv').config();
const cors = require("cors")
const app = express();
const PORT = 8000;

// Replace with your credentials
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const JWT_SECRET = process.env.JWT_SECRET; // Secret key for signing JWTs

// Middleware: Cookie Session

app.use(
  cookieSession({
    name: 'session',
    keys: ['random_secret_key'], // Replace with secure keys
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
  })
);

app.use(cors({
  origin:"http://localhost:3000",
  methods:"GET,POST,PUT,DELETE",
  credentials:true
}))

// Initialize Passport.js
app.use(passport.initialize());
app.use(passport.session());

// Configure Passport.js Google Strategy
passport.use(
  new GoogleStrategy(
    {
      clientID: GOOGLE_CLIENT_ID,
      clientSecret: GOOGLE_CLIENT_SECRET,
      callbackURL: 'http://localhost:8000/auth/google/callback',
    },
    (accessToken, refreshToken, profile, done) => {
      // Create a user object with relevant data
      const user = {
        id: profile.id,
        name: profile.displayName,
        email: profile.emails[0].value,
      };

      // Pass the user to the next middleware
      done(null, user);
    }
  )
);

// Serialize and Deserialize User (required by Passport)
passport.serializeUser((user, done) => {
  done(null, user); // Store the entire user object in the cookie
});

passport.deserializeUser((user, done) => {
  done(null, user); // Retrieve the user object from the cookie
});

// Routes

// Login Route: Redirects to Google for authentication
app.get(
  '/auth/google',
  passport.authenticate('google', {
    scope: ['profile', 'email'],
  })
);

// Callback Route: Handles Google OAuth response
app.get(
  '/auth/google/callback',
  passport.authenticate('google', { session: true }), // Use session for cookie storage
  (req, res) => {
    console.log('User authenticated:', req.user); // Log the authenticated user

    // Generate a JWT after successful authentication
    const token = jwt.sign(req.user, JWT_SECRET, { expiresIn: '7d' });

    // Send the JWT and user data to the client
    res.json({
      token, // Send the JWT token to the client
      user: req.user, // Send the user data to the client
    });
  }
);

// Middleware to Protect Routes: Verifies JWT
const verifyToken = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1]; // Extract token from Authorization header
  if (!token) {
    return res.status(401).json({ message: 'Unauthorized, no token provided' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET); // Verify the JWT
    req.user = decoded; // Attach user info to the request
    next();
  } catch (err) {
    return res.status(403).json({ message: 'Invalid token' });
  }
};

// Protected Route: Example of a route that requires authentication
app.get('/api/protected', verifyToken, (req, res) => {
  res.json({
    message: `Welcome, ${req.user.name}!`,
  });
});

// Protected Route to check user info
app.get('/me', (req, res) => {
  if (req.isAuthenticated()) {
    res.status(200).json(req.user); // Send the authenticated user's data
  } else {
    res.status(401).json({ message: 'Not authenticated' });
  }
});

// Logout Route
app.get('/auth/logout', (req, res) => {
  req.logout(() => {
    req.session = null; // Clear the session cookie
    res.json({ message: 'Logged out successfully' });
  });
});

// Home Route
app.get('/', (req, res) => {
  res.send('Welcome to the Passport.js Google OAuth Example!');
});

// Start the Server
app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
