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
  const query = req.query || {}
  const body = req.body || {}
  if (query.requestSSO === 'true' || body.requestSSO === 'true') {
    const sp = query.sp || body.sp
    const relayState = query.relayState || body.RelayState
    const id = query.id || body.id
    const destination = query.destination || body.destination
    const acsUrl = query.acsUrl || body.acsUrl
    return res.redirect(
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
