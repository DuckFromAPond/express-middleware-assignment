const express = require('express');
const basicAuth = require('express-basic-auth');
const { IpFilter, IpDeniedError } = require('express-ipfilter');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const hbs = require('hbs');
const path = require('path');

require('dotenv').config();

const app = express();
const PORT = 3000;

// custom greater & less than helper for hbs 
hbs.registerHelper('gt', function(a, b) {
  return a > b;
});
hbs.registerHelper('lt', function(a, b) {
  return a < b;
});

// price object 
const price = {
  "market": "Global Energy Exchange",
  "last_updated": "2026-03-15T12:55:00Z",
  "currency": "USD",
  "data": [
    {
      "symbol": "WTI",
      "name": "West Texas Intermediate",
      "price": 78.45,
      "change": 0.12
    },
    {
      "symbol": "BRENT",
      "name": "Brent Crude",
      "price": 82.30,
      "change": -0.05
    },
    {
      "symbol": "NAT_GAS",
      "name": "Natural Gas",
      "price": 2.15,
      "change": 0.02
    }
  ]
}

// Middleware set up
// IP whtielist 
const ips = ['127.0.0.1', '::1'];
app.use(IpFilter(ips, { mode: 'allow' }));

// bearer-token api set up
const SECRET = process.env.SECRET || 'NOT_SO_SECRET_SECRET';  // get secret from env
// helper function to check header for token 
function bearerAuth(req, res, next) {
  // get header 
  const authHeader = req.get('Authorization');

  // validate header 
  if (!authHeader || !authHeader.startsWith('Bearer ')) { 
    return res.status(401).send({error: "Invalid Bearer token"});
  }
  
  // get the token from the header
  const key = authHeader.split(' ')[1];

  try {
    // decode token
    const decoded = jwt.verify(key, SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    // invalid token
    return res.status(401).send({error: "Incorrect Bearer token; Permission denied"});
  }
}

// basic auth set up
const auth = basicAuth({
  users: {'user': '123'}, 
  challenge: true, 
  realm: 'myrealm '
})

// Set up hbs as the view engine
app.set('view engine', 'hbs');
app.set('views', path.join(__dirname, 'views'));

// Rate limiter set up 
const option = {
    windowMs: 60 * 1000,   // 1 minutes
    max: 10,               // limit requests to 10
    standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
    legacyHeaders: false,  // Disable the `X-RateLimit-*` headers
    message: 'Too many requests from this IP, please try again after a minute'
}
app.use(rateLimit(option));

// CORS set up 
app.use(cors({
  origin: 'http://localhost:3000', // only allow local development origin
}));

// get / - redirect to dashboard 
app.get('/', (req, res) => {
  res.redirect('/dashboard');
});

// get /dashboard - Render UI showing data 
app.get('/dashboard', auth, (req, res) => {
  // format ISO time 
  const formattedDate = new Date(price.last_updated).toLocaleString();

  // generate Bearer token using username
  const username = req.auth.user;
  const token = jwt.sign(
    { username }, SECRET,
    {  expiresIn: '1h' }
  );

  console.log(`bearer token: ${token}`);

  // render dashboard with prices passed in
  res.render('dashboard', {price: {...price, last_updated: formattedDate}});
});

// get /api/oil-prices - return oil prices obj
app.get('/api/oil-prices', bearerAuth,(req,res) => {
  res.json(price);
})

// get /logout - redirects to a "Logged Out" message (no UI)
app.get('/logout', (req, res) => {
  res.status(401).send('Logged Out');
})

// Error handling for disallowed ip
app.use((err, req, res, next) => {
  if (err instanceof IpDeniedError) {
    return res.status(403).send('Forbidden: Your IP is not allowed');
  }

  next(err);
});

app.listen(PORT, () => {
  console.log('Running on http://localhost:3000');
});