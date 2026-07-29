// server/users.js
// Example Express router providing /api/users endpoints protected by verifyAdmin.
// This file assumes you have a top-level server that initializes firebase-admin
// and mounts this router, for example:
//   const admin = require('firebase-admin'); admin.initializeApp({ ... });
//   const firestore = admin.firestore();
//   const usersRouter = require('./server/users')(admin, firestore);
//   app.use('/api', usersRouter);

const express = require('express');
const bcrypt = require('bcrypt');

module.exports = function(admin, firestore) {
  const router = express.Router();
  const verifyAdmin = require('./middleware/verifyAdmin')(admin, firestore);

  // List users (admin only)
  router.get('/users', verifyAdmin, async (req, res) => {
    try {
      const snap = await firestore.collection('users').get();
      const users = snap.docs.map(d => ({ id: d.id, ...d.data() }));
      // Never return password hashes
      users.forEach(u => delete u.password);
      res.json(users);
    } catch (err) {
      console.error('/api/users GET error', err);
      res.status(500).json({ error: 'Failed to list users' });
    }
  });

  // Create user
  router.post('/users', verifyAdmin, async (req, res) => {
    try {
      const { name, email, role, password } = req.body || {};
      if (!email || !name) return res.status(400).json({ error: 'name and email are required' });

      // If password provided, create Auth user in Firebase Auth. Otherwise create only Firestore doc.
      let authUser = null;
      if (password) {
        // Create user in Firebase Auth
        authUser = await admin.auth().createUser({
          email,
          password,
          displayName: name
        });
      }

      const docRef = authUser ? firestore.collection('users').doc(authUser.uid) : firestore.collection('users').doc();
      const docData = {
        name,
        email,
        role: role || 'user',
        createdAt: admin.firestore.FieldValue.serverTimestamp()
      };

      await docRef.set(docData);
      res.status(201).json({ id: docRef.id, ...docData });
    } catch (err) {
      console.error('/api/users POST error', err);
      // If createUser failed with email exists, bubble up helpful message
      res.status(500).json({ error: err.message || 'Failed to create user' });
    }
  });

  // Update user
  router.put('/users/:id', verifyAdmin, async (req, res) => {
    try {
      const id = req.params.id;
      const { name, email, role, password } = req.body || {};
      const docRef = firestore.collection('users').doc(id);
      const doc = await docRef.get();
      if (!doc.exists) return res.status(404).json({ error: 'User not found' });

      const updates = {};
      if (name) updates.name = name;
      if (email) updates.email = email;
      if (role) updates.role = role;
      updates.updatedAt = admin.firestore.FieldValue.serverTimestamp();

      // Update auth user when possible (if a corresponding auth user exists with same uid)
      try {
        // Attempt to update Firebase Auth user (this will fail silently if uid is not an auth user)
        await admin.auth().updateUser(id, {
          ...(email ? { email } : {}),
          ...(password ? { password } : {}),
          ...(name ? { displayName: name } : {})
        });
      } catch (e) {
        // Not critical — the Firestore user may not map to Auth user by id
        console.warn('update user: could not update firebase auth user', e.message || e);
      }

      await docRef.update(updates);
      res.json({ ok: true });
    } catch (err) {
      console.error('/api/users PUT error', err);
      res.status(500).json({ error: 'Failed to update user' });
    }
  });

  // Delete user
  router.delete('/users/:id', verifyAdmin, async (req, res) => {
    try {
      const id = req.params.id;
      const docRef = firestore.collection('users').doc(id);
      const doc = await docRef.get();
      if (!doc.exists) return res.status(404).json({ error: 'User not found' });

      // Attempt to delete corresponding Firebase Auth user (if exists)
      try {
        await admin.auth().deleteUser(id);
      } catch (e) {
        // If the user id wasn't an auth user, ignore the error
        console.warn('deleteUser: could not delete firebase auth user', e.message || e);
      }

      await docRef.delete();
      res.json({ ok: true });
    } catch (err) {
      console.error('/api/users DELETE error', err);
      res.status(500).json({ error: 'Failed to delete user' });
    }
  });

  return router;
};
