// server/middleware/verifyAdmin.js
// Factory that returns Express middleware. Pass initialized `admin` and `firestore` instances.
// Usage: const verifyAdmin = require('./middleware/verifyAdmin')(admin, firestore);
module.exports = function(admin, firestore) {
  return async function verifyAdmin(req, res, next) {
    try {
      const authHeader = req.headers.authorization || '';
      const idToken = authHeader.startsWith('Bearer ') ? authHeader.split('Bearer ')[1] : null;
      if (!idToken) {
        return res.status(401).json({ error: 'Missing or invalid Authorization header' });
      }

      const decoded = await admin.auth().verifyIdToken(idToken);
      // Fast path: custom claim
      if (decoded.admin === true) {
        req.user = decoded;
        return next();
      }

      // Fallback: check Firestore users collection for role
      try {
        const userDoc = await firestore.collection('users').doc(decoded.uid).get();
        const role = userDoc.exists ? userDoc.data().role : null;
        if (role === 'admin') {
          req.user = decoded;
          return next();
        }
      } catch (e) {
        console.warn('verifyAdmin: firestore lookup failed', e);
      }

      return res.status(403).json({ error: 'Forbidden: admin only' });
    } catch (err) {
      console.error('verifyAdmin error:', err);
      return res.status(401).json({ error: 'Invalid token' });
    }
  };
};
