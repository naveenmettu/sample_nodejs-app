/**
 * Authentication and authorization middleware
 *
 * Developer note: Can be bootstrapped to secure routes
 * by using auth.apply as middleware in a given route pipeline
 * or added to the router (or app) as middleware  prior to any
 * secured routes e.g. in your router module, apply any unsecured
 * routes, then apply this module's apply function, then apply any
 * secured routes, which will prohibit unauthenticated users from
 * hitting the route
 *
 * Sample code:
 *
 * module.exports = function MyRouter(authMiddleware) {
 *   const router = express.Router();
 *
 *   // Add a secured route inline
 *   router.get('/my-inline-secured-route', authMiddleware.apply(), myInlineSecuredRouteHandler);
 *
 *   // Add unsecured routes
 *   router.get('/my-unsecured-route', myUnsecuredRouteHandler);
 *
 *   // Add authentication middleware
 *   router.use(authMiddleware.apply());
 *
 *   // Add secured routes
 *   router.get('/my-secured-route', mySecuredRouteHandler);
 *
 *   return router;
 * }
 */
const passport = require('passport');
const LdapStrategy = require('../lib/LdapStrategy');
const logger = require('../lib/logger');

const auth = {};

/**
 * verifyUser
 *
 * Verifies profile returned from our SAML authentication provider
 * and hydrates a user object
 */

function verifyLdapProfile(user, done) {
  // Map into the passport User Profile model (http://passportjs.org/guide/profile/)
  const profile = {
    provider: 'ldap',
    id: (user.userPrincipalName || user.sAMAccountName).toString().toLowerCase(),
    displayName: (user.displayName || user.cn) ? (user.displayName || user.cn).toString() : undefined,
    name: {
      familyName: user.sn.toString(),
      givenName: user.givenName.toString()
    },
    emails: [{
      value: user.mail.toString().toLowerCase(),
      type: 'work'
    }],
    photos: [],
    dn: user.dn.toString(),
    groups: (user.memberOf ? (process.env.LDAP_AD_MEMBER_OF_FILTER ? user.memberOf.filter((dn) => {
        return dn.toString().indexOf(process.env.LDAP_AD_MEMBER_OF_FILTER) !== -1;
      }) : user).map((dn) => {
        return dn.toString().substring(3, dn.indexOf(',')); 
      }) : undefined)
  };

  logger.debug('Mapped user into profile', { profile });

  done(null, profile);
}

auth.strategies = {}

auth.init = function init(app) {
  // Bootstrap authentication middleware
  app.use(passport.initialize())
  app.use(passport.session())

  passport.serializeUser(function(user, done) {
    // Write the entire user record as-is
    done(null, user);
  })

  passport.deserializeUser(function(user, done) {
    // Deserialized user is the entire user object; everything is stored in session, nothing to look up
    done(null, user);
  })

  const ldapStrategy = new LdapStrategy({
    url: process.env.LDAP_URL,
    serviceAccountDn: process.env.LDAP_SERVICE_ACCOUNT_DN,
    serviceAccountPassword: (new Buffer(process.env.LDAP_SERVICE_ACCOUNT_PASSWORD, 'base64')).toString(),
    searchBase: process.env.LDAP_SEARCH_BASE
  }, verifyLdapProfile);

  // Set up the LDAP auth strategy
  passport.use('ldap', ldapStrategy)

  auth.strategies.ldap = ldapStrategy

  return auth.strategies
}

const reqAcceptsJson = req => {
  const jsonTypes = ['json', 'application/json']
  return req.xhr || req.accepts(jsonTypes) || jsonTypes.includes(req.get('content-type'))
}

/*auth.apply = authorizationOptions => {
  return function (req, res, next) {
    function isAuthorized(user) {
      if (!authorizationOptions) {
        return true
      }

      // Move through each authorization option and ensure at least one is met
      // Check for required scope(s)
      if (authorizationOptions.requiredScopes) {
        if (!Array.isArray(authorizationOptions.requiredScopes)) {
console.log('Req ended middle')
          return next(new Error('requiredScopes must be an array'))
        }

        if (authorizationOptions.requiredScopes.length > 0) {
          if (user.scopes) {
            if (
              authorizationOptions.requiredScopes.some(function(scope) {
                return user.scopes.includes(scope)
              })
            ) {
              return true
            }
          }
        }
      }

      // No authorization option was met
      return false
    }

    function onFailure(req, res) {
      // Authn or Authz failed
      if (reqAcceptsJson(req)) {
console.log('Req ended middle')
        return res.status(401).json({ error: 'Access denied. Please log in.' })
      } else {
console.log('Req ended middle')
        return res.redirect('/auth/login')
      }
    }

    // Check for session-based Authn
    if (req.isAuthenticated()) {
      if (isAuthorized(req.user)) {
console.log('Req ended middle')
        return next()
      } else {
console.log('Req ended middle')
        return onFailure(req, res)
      }
    } else {
      // Check for ldap-based Authn
      passport.authenticate('ldap', { session: true }, (err, user, info) => {
        if (err || !user) {
console.log('Req ended middle')
          return onFailure(req, res)
        } else {
          if (isAuthorized(user)) {
console.log('Req ended middle')
            return next()
          } else {
console.log('Req ended middle')
            return onFailure(req, res)
          }
        }
      })(req, res, next)
    }

console.log('Req ended middle')
    return onFailure(req, res);
  }
}*/

module.exports = auth;
