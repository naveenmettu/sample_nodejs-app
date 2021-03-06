const samlp = require('samlp')
const logger = require('./logger')

class IdentityProvider {
  constructor(options) {
    this.options = {
      issuer: options.issuer,
      cert: options.cert,
      key: options.key,
      sloUrl: options.sloUrl,
      signatureAlgorithm: options.signatureAlgorithm || 'rsa-sha256',
      signResponse: options.signResponse || true,
      encryptAssertion: options.encryptAssertion || false,
      encryptionCert: options.encryptionCert,
      encryptionPublicKey: options.encryptionPublicKey,
      encryptionAlgorithm: options.encryptionAlgorithm,
      keyEncryptionAlgorithm: options.keyEncryptionAlgorithm,
      lifetimeInSeconds: options.lifetimeInSeconds || 3600,
      authnContextClassRef: options.authnContextClassRef,
      authnContextDecl: options.AuthnContextDecl,
      includeAttributeNameFormat: options.includeAttributeNameFormat || true,
      postEndpointPath: options.postEndpointPath,
      redirectEndpointPath: options.redirectEndpointPath,
      logoutEndpointPaths: options.logoutEndpointPaths,
      getUserFromRequest: options.getUserFromRequest,
      getPostURL: (audience, authnRequestDom, req, callback) => {
        if (this.serviceProviders[audience]) {
          let url = this.serviceProviders[audience].recipient
          if (
            req.authnRequest &&
            req.authnRequest.acsUrl &&
            req.authnRequest.acsUrl !== this.serviceProviders[audience].recipient
          ) {
            if (
              this.serviceProviders[audience].acceptedAcsUrls &&
              this.serviceProviders[audience].acceptedAcsUrls.includes(req.authnRequest.acsUrl)
            ) {
              url = req.authnRequest.acsUrl
            } else {
              const message = `Unacceptable ACS URL received in authentication request: ${
                req.authnRequest.acsUrl
              }`
              log.warn(message, { authnRequest: req.authnRequest })
              return callback(new Error(message))
            }
          }

          return callback(null, url)
        }

        const message = `Unrecognized service provider [${options.issuer}]`
        logger.warn(message, { options })
        return callback(new Error(message))
      },
      responseHandler: options.responseHandler
      /*,
      transformAssertion:     function(assertionDom) {
                                if (argv.authnContextDecl) {
                                  var declDoc;
                                  try {
                                    declDoc = new Parser().parseFromString(argv.authnContextDecl);
                                  } catch(err){
                                    logger.warn('Unable to parse Authentication Context Declaration XML', err);
                                  }
                                  if (declDoc) {
                                    const authnContextDeclEl = assertionDom.createElementNS('urn:oasis:names:tc:SAML:2.0:assertion', 'saml:AuthnContextDecl');
                                    authnContextDeclEl.appendChild(declDoc.documentElement);
                                    const authnContextEl = assertionDom.getElementsByTagName('saml:AuthnContext')[0];
                                    authnContextEl.appendChild(authnContextDeclEl);
                                  }
                                }
                              },
      responseHandler:        function(response, opts, req, res, next) {
                                logger.info(`Sending SAMLResponse to ${opts.postUrl} with RelayState ${opts.RelayState} =>\n${xmlFormat(response.toString(), {indentation: '  '})}`, );
                                res.render('samlresponse', {
                                  AcsUrl: opts.postUrl,
                                  SAMLResponse: response.toString('base64'),
                                  RelayState: opts.RelayState
                                });
                              }*/
    }

    this.serviceProviders = options.serviceProviders
  }

  parseSignInRequest(req, callback) {
    const options = {}

    // Look for a current user
    if (req.isAuthenticated()) {
      options.username = req.user.id
    }

    const query = req.query || {}
    const body = req.body || {}

    // Look for a URL-based SSO request
    options.issuer = query.sp || body.sp

    // Look for relay state
    options.relayState = query.relayState || body.RelayState

    // Look for other options that may come through in a redirect after login
    options.id = query.id || body.id
    options.destination = query.destination || body.destination
    options.acsUrl = query.acsUrl || body.acsUrl

    // Look for a SAML Request
    samlp.parseRequest(req, (err, data) => {
      if (err) {
        const message = 'Error parsing SAML Authentication Request'
        log.warn(message, { error: err })
        return callback(new Error(message))
      }

      if (data) {
        // If information has been provided twice, ensure they match
        if (options.issuer && data.issuer && data.issuer !== options.issuer) {
          const message = 'Service provider requested in URL does not match issuer of SAML request'
          log.warn(message, {
            requestedServiceProviderId: options.issuer,
            SAMLRequest: data
          })
          return callback(new Error(message))
        }

        options.id = data.id
        options.issuer = options.issuer || data.issuer
        options.destination = data.destination
        options.acsUrl = data.assertionConsumerServiceURL
        options.forceAuthn = data.forceAuthn === 'true'
      }

      const spOptions = this.serviceProviders[options.issuer]

      if (!spOptions) {
        const message = `Unrecognized service provider [${options.issuer}]`
        logger.warn(message, { options })
        return callback(new Error(message))
      }

      let url = spOptions.recipient

      if (options.acsUrl && options.acsUrl !== spOptions.recipient) {
        if (spOptions.acceptedAcsUrls && spOptions.acceptedAcsUrls.includes(options.acsUrl)) {
          url = options.acsUrl
        } else {
          const message = `Unacceptable ACS URL received in authentication request: [${
            req.authnRequest.acsUrl
          }]`
          log.warn(message, { options })
          return callback(new Error(message))
        }
      }
      options.acsUrl = url

      logger.info('Parsed sign-in request', { options })

      return callback(null, options)
    })
  }

  signIn(options) {
    const serviceProvider = this.serviceProviders[options.issuer]

    // Explicitly copy this.options into authOptions so that we don't
    // accidentally copy security stuff into our log file if we later add
    // new properties to this.options
    const authOptions = {
      id: options.id,
      audience: options.issuer,
      cert: this.options.cert,
      sloUrl: this.options.sloUrl,
      signatureAlgorithm: this.options.signatureAlgorithm,
      signResponse: this.options.signResponse,
      encryptAssertion: this.options.encryptAssertion,
      lifetimeInSeconds: this.options.lifetimeInSeconds,
      includeAttributeNameFormat: this.options.includeAttributeNameFormat,
      postEndpointPath: this.options.postEndpointPath,
      redirectEndpointPath: this.options.redirectEndpointPath,
      logoutEndpointPaths: this.options.logoutEndpointPaths,
      inResponseTo: options.id,
      destination: options.destination,
      recipient: options.acsUrl,
      allowRequestAcsUrl: serviceProvider.allowRequestAcsUrl,
      signingCert: serviceProvider.signingCert,
      digestAlgorithm: serviceProvider.digestAlgorithm,
      acsUrl: options.acsUrl,
      forceAuthn: options.forceAuthn,
      RelayState: options.relayState
    }

    const loggedOptions = { ...authOptions }
    loggedOptions.key = '-----REDACTED-----'
    logger.info('Processing SAML-P authentication request', { loggedOptions })

    // Copy in the rest of the properties that we don't want logged
    authOptions.key = this.options.key

    // Copy function-based options
    authOptions.getUserFromRequest = this.options.getUserFromRequest
    authOptions.getPostURL = this.options.getPostURL
    authOptions.transformAssertion = this.options.transformAssertion
    authOptions.responseHandler = this.options.responseHandler

    return samlp.auth(authOptions)
  }

  renderMetadata() {
    return samlp.metadata(this.idpOptions)
  }
}

exports = module.exports = IdentityProvider
