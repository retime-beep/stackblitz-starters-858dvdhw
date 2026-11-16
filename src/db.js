'use strict';

require('dotenv').config();
const { createClient } = require('@supabase/supabase-js');

const {
  SUPABASE_URL,
  SUPABASE_PUBLISHABLE_KEY,
  SUPABASE_SECRET_KEY,
} = process.env;

for (const [k, v] of Object.entries({ SUPABASE_URL, SUPABASE_PUBLISHABLE_KEY, SUPABASE_SECRET_KEY })) {
  if (!v) throw new Error(`Missing ${k}. Check your .env file.`);
}

const opts = { auth: { persistSession: false, autoRefreshToken: false } };

// Full access, bypasses RLS. Server-side only. NEVER send this key to a client.
const supabase = createClient(SUPABASE_URL, SUPABASE_SECRET_KEY, opts);

// Used only to log users in with email + password.
const anon = createClient(SUPABASE_URL, SUPABASE_PUBLISHABLE_KEY, opts);

module.exports = { supabase, anon };