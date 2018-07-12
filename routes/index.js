const express = require('express')
const path = require('path')
const passport = require('passport')
const logger = require('../lib/logger')

const router = express.Router()

const authRouter = require('./auth')
const idpRouter = require('./idp')

router.use('/auth', authRouter)
router.use('/idp', idpRouter)

router.get(
  '/',
  (req, res, next) => {
    passport.authenticate('ldap', { failureRedirect: '/auth/login' })(req, res, next)
  },
  (req, res, next) => {
    res.render('home', { username: req.user.id })
  }
)

// Fallback: check static client files
router.use('/', express.static(path.join(__dirname, '../static')))

logger.info('Bootstrapped routes')

module.exports = router
