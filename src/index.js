'use strict';

const express = require('express');
const { supabase, anon } = require('./db');
const { requireAuth } = require('./auth');

const app = express();
app.use(express.json());

app.get('/health', (req, res) => res.json({ ok: true }));

// Create an account: Supabase Auth user + matching row in our users table.
app.post('/signup', async (req, res) => {
  const { email, password, username } = req.body || {};
  if (!email || !password || !username) {
    return res
      .status(400)
      .json({ error: 'email, password and username are required' });
  }
  if (
    typeof username !== 'string' ||
    username.length < 2 ||
    username.length > 32
  ) {
    return res.status(400).json({ error: 'username must be 2-32 characters' });
  }

  const { data, error } = await supabase.auth.admin.createUser({
    email,
    password,
    email_confirm: true, // skip email verification while developing
  });
  if (error) return res.status(400).json({ error: error.message });

  const { error: profileError } = await supabase
    .from('users')
    .insert({ id: data.user.id, username });

  if (profileError) {
    // Roll back the auth account so the email isn't stuck half-registered.
    await supabase.auth.admin.deleteUser(data.user.id);
    const taken = profileError.code === '23505';
    if (!taken) console.error(profileError);
    return res
      .status(taken ? 409 : 500)
      .json({
        error: taken ? 'username already taken' : 'could not create profile',
      });
  }

  res.status(201).json({ id: data.user.id });
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password)
    return res.status(400).json({ error: 'email and password are required' });

  const { data, error } = await anon.auth.signInWithPassword({
    email,
    password,
  });
  if (error) return res.status(401).json({ error: 'invalid credentials' });

  res.json({ access_token: data.session.access_token });
});

// Create a server. The caller becomes the owner.
app.post('/servers', requireAuth, async (req, res) => {
  const name = String((req.body && req.body.name) || '').trim();
  if (name.length < 1 || name.length > 100) {
    return res.status(400).json({ error: 'name must be 1-100 characters' });
  }

  const { data, error } = await supabase.rpc('create_server', {
    p_owner: req.user.id,
    p_name: name,
  });
  if (error) {
    console.error(error);
    return res.status(500).json({ error: 'could not create server' });
  }

  res.status(201).json({ id: data });
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Burrow backend listening on ${port}`));
