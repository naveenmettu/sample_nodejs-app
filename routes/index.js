const express = require('express');
const path = require('path');
const passport = require('passport');

const router = express.Router();

const authRouter = require('./auth');

router.use('/auth', authRouter);

router.get('/', passport.authenticate('ldap', { failureRedirect: '/auth/login' }), (req, res, next) => {
  res.render('home', { username: req.user.username });
});

// Fallback: check static client files
router.use('/', express.static(path.join(__dirname, '../static')));

console.log('Bootstrapped routes');

module.exports = router;