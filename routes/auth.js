const express = require('express');
const passport = require('passport');
//const authMiddleware = require('../middleware/auth');

const router = express.Router();

const ROUTES = {
  LOGIN: '/login'
}

function renderLogin(req, res) {
  res.render('login');
}

function login(req, res) {
  res.redirect('/');
}

router.get(ROUTES.LOGIN, renderLogin);
router.post(ROUTES.LOGIN, passport.authenticate('ldap', { successRedirect: '/', failureRedirect: '/auth/login' }), login);

module.exports = router;
