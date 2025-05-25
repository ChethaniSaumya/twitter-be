// middleware/authenticate.js (create this file or put it at top of server.js)

function authenticate(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader) {
    return res.status(401).json({ error: 'No authorization header' });
  }

  const token = authHeader.split(' ')[1]; // Bearer TOKEN

  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }

  // For demo, accept a fixed token, or replace with real verification logic
  if (token === 'your-secret-token') {
    // authorized
    next();
  } else {
    res.status(403).json({ error: 'Invalid token' });
  }
}

module.exports = { authenticate };
