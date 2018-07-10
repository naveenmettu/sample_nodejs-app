const express = require('express')
const logger = require('../lib/logger')
const IdentityProvider = require('../lib/IdentityProvider')

const router = express.Router()

const ROUTES = {
  SIGN_IN: '/sso',
  SIGN_OUT: '/logout',
  METADATA: '/metadata'
}

const spOptions = require('../service-provider-config.json')

function handleSamlResponse(response, opts, req, res, next) {
  logger.info('Processing SAML Response', {
    user: req.user,
    response: response.toString('base64'),
    destination: opts.postUrl,
    RelayState: opts.RelayState
  })

  res.render('saml-response', {
    AcsUrl: opts.postUrl,
    SAMLResponse: response.toString('base64'),
    RelayState: opts.RelayState
  })
}

const idp = new IdentityProvider({
  issuer: process.env.IDP_ENTITY_ID,
  cert: process.env.IDP_SIGNING_CERT,
  key: process.env.IDP_SIGNING_CERT_PRIVATE_KEY,
  sloUrl: `${process.env.HOSTING_EXTERNAL_BASE_URL}/idp${ROUTES.SIGN_OUT}`,
  signatureAlgorithm: process.env.IDP_SIGNATURE_ALGORITHM,
  signResponse: process.env.IDP_SIGN_RESPONSE,
  encryptAssertion: process.env.IDP_ENCRYPT_ASSERTION === 'true',
  encryptionCert: process.env.IDP_ENCRYPTION_CERT_PRIVATE_KEY,
  encryptionPublicKey: process.env.IDP_ENCRYPTION_CERT,
  encryptionAlgorithm: process.env.IDP_ENCRYPTION_ALGORITHM,
  keyEncryptionAlgorithm: process.env.IDP_KEY_ENCRYPTION_ALGORITHM,
  lifetimeInSeconds: process.env.IDP_ASSERTION_LIFETIME_IN_SECONDS || 3600,
  authnContextClassRef: process.env.IDP_AUTHENTICATION_CONTEXT_CLASS_REF,
  authnContextDecl: process.env.IDP_AUTHENTICATION_CONTEXT_CLASS_DECLARATION,
  includeAttributeNameFormat:
    process.env.IDP_INCLUDE_ATTRIBUTE_NAME_FORMAT === 'false' ? false : true,
  postEndpointPath: `/idp${ROUTES.SIGN_IN}`,
  redirectEndpointPath: `/idp${ROUTES.SIGN_IN}`,
  logoutEndpointPaths: {
    redirect: `/idp${ROUTES.SIGN_OUT}`,
    post: `/idp${ROUTES.SIGN_OUT}`
  },
  responseHandler: handleSamlResponse,
  serviceProviders: spOptions
})

/**
 * signIn
 *
 * Parses and validates SSO request, then signs in or prompts user for login
 *
 */
function signIn(req, res, next) {
  return idp.parseSignInRequest(req, (err, authenticationOptions) => {
    if (err) {
      return res.render('error', {
        message: `Unable to parse sign-in request or validation failed: ${err.message}`
      })
    }

    if (req.isAuthenticated()) {
      req.authnRequest = authenticationOptions
      return idp.signIn(authenticationOptions)(req, res, next)
    }

    authenticationOptions.requestSso = true
    authenticationOptions.spName = spOptions[authenticationOptions.issuer].name
    return res.render('login', authenticationOptions)
  })
}

function signOut(req, res) {
  // TODO: Support single sign-out URL for SP
  req.logout()
  if (req.session) {
    return req.session.destroy(function(err) {
      if (err) {
        throw err
      }
      return res.redirect('back')
    })
  }

  return res.redirect('back')
}

function getMetadata(req, res) {
  return idp.getMetadata()(req, res)
}

router.get(ROUTES.SIGN_IN, signIn)

router.post(ROUTES.SIGN_IN, signIn)

router.get(ROUTES.SIGN_OUT, signOut)

router.post(ROUTES.SIGN_OUT, signOut)

router.get(ROUTES.METADATA, getMetadata)

module.exports = router
