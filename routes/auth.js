const express = require('express')
const passport = require('passport')
//const authMiddleware = require('../middleware/auth');

const router = express.Router()

const ROUTES = {
  LOGIN: '/login'
}

function renderLogin(req, res) {
  res.render('login')
}

function login(req, res) {
  if ((req.query || {}).requestSSO === 'true' || (req.body || {}).requestSSO === 'true') {
    const sp = (req.query || {}).sp || (req.body || {}).sp
    const relayState = (req.query || {}).relayState || (req.body || {}).RelayState
    const id = (req.query || {}).id || (req.body || {}).id
    const destination = (req.query || {}).destination || (req.body || {}).destination
    const acsUrl = (req.query || {}).acsUrl || (req.body || {}).acsUrl
    res.redirect(
      `/idp/sso?sp=${encodeURIComponent(sp)}&id=${encodeURIComponent(
        id
      )}&destination=${encodeURIComponent(destination)}&acsUrl=${encodeURIComponent(
        acsUrl
      )}&relayState=${encodeURIComponent(relayState)}`
    )
  }
  res.redirect('/')
}

router.get(ROUTES.LOGIN, renderLogin)
router.post(ROUTES.LOGIN, passport.authenticate('ldap', { failureRedirect: '/auth/login' }), login)

module.exports = router
