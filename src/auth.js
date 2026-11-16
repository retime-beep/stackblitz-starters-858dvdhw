'use strict';

const { supabase } = require('./db');

// Express middleware: expects "Authorization: Bearer <access_token>".
async function requireAuth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'missing token' });

  const { data, error } = await supabase.auth.getUser(token);
  if (error || !data || !data.user)
    return res.status(401).json({ error: 'invalid token' });

  req.user = data.user; // req.user.id matches users.id
  next();
}

module.exports = { requireAuth };
