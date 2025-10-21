 ### How to fix (server-side) with tiny code examples
# 1) Lock down the session cookie

Stop most cross-site requests from carrying your session in the first place.
```
// Express/Node
app.use(require('express-session')({
  name: 'sid',
  secret: process.env.SESSION_SECRET,
  resave: false, saveUninitialized: false,
  cookie: { httpOnly: true, secure: true, sameSite: 'lax', maxAge: 3600_000 }
}));

```
# 2) Require a CSRF token on every state-changing request

Only pages from your site can read & send this back.

const crypto = require('crypto');

```

// after login
app.post('/login', (req,res)=>{ req.session.userId='123';
  req.session.csrf = crypto.randomBytes(32).toString('base64url'); res.json({ok:true}); });

// SPA fetches token
app.get('/csrf-token',(req,res)=> res.json({ csrf: req.session.csrf }));

// check token
function requireCsrf(req,res,next){
  if (req.get('X-CSRF-Token') !== req.session.csrf) return res.status(403).json({error:'Invalid CSRF'});
  next();
}

```

# 3) Validate Origin/Referer on POST/PUT/PATCH/DELETE

Block cross-site requests even if cookies slip through.

```
const ORIGIN = 'https://vulnerable-social.com';
function sameOrigin(req,res,next){
  if (!['POST','PUT','PATCH','DELETE'].includes(req.method)) return next();
  const o = req.headers.origin, r = req.headers.referer;
  if ((o && o!==ORIGIN) || (!o && r && !r.startsWith(ORIGIN)))
    return res.status(403).json({error:'Bad origin'});
  next();
}

```

# 4) Gate by content type & headers, and don’t open CORS

Force JSON + custom header; cross-site fetches hit a CORS preflight you don’t allow.

```
function jsonAjaxOnly(req,res,next){
  if (!req.is('application/json')) return res.status(415).json({error:'Use JSON'});
  if (req.get('X-Requested-With') !== 'XMLHttpRequest')
    return res.status(400).json({error:'Missing X-Requested-With'});
  next();
}

```
// ❌ Do NOT enable wide-open CORS with credentials.

# 5) Step-up auth for sensitive changes (like email)

Even if something slipped, attacker can’t change email without re-auth.
```

function requirePasswordWhenChangingEmail(req,res,next){
  if (!req.body.email) return next();
  if (req.body.currentPassword !== 'demo-password') // replace with real check
    return res.status(401).json({error:'Re-auth required to change email'});
  next();
}
```

# 6) Put it together on the protected route (order matters)

function requireAuth(req,res,next){ if(!req.session.userId) return res.status(401).json({error:'Unauth'}); next(); }

app.post('/api/profile/update',
  sameOrigin,              // block cross-site
  requireAuth,             // must be logged in
  jsonAjaxOnly,            // only JSON + custom header
  requireCsrf,             // token must match
  requirePasswordWhenChangingEmail, // step-up for email change
  (req,res)=> res.json({ ok:true, updated:{ email:req.body.email, bio:req.body.bio } })
);


Why this works:

SameSite cookie usually stops cookies on cross-site requests.

Origin/Referer check rejects anything not from your site.

JSON + custom header triggers CORS preflight cross-site (which you deny).

CSRF token blocks forged requests that can’t read your token.

Step-up auth protects high-risk changes.