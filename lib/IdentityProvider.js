const samlp = require('samlp');
const logger = require('./logger');

const IdentityProvider = function (options, serviceProviderOptions) {
  const self = this;

  self.options = {
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
    getPostURL: function (audience, authnRequestDom, req, callback) {
      if (self.spOptions[audience]) {
        let url = self.spOptions[audience].recipient;
        if (req.authnRequest && req.authnRequest.acsUrl && req.authnRequest.acsUrl !== self.spOptions[audience].recipient) {
          if (self.spOptions[audience].acceptedAcsUrls
            && self.spOptions[audience].acceptedAcsUrls.includes(req.authnRequest.acsUrl)) {
            url = req.authnRequest.acsUrl;
          } else {
            const message = `Unacceptable ACS URL received in authentication request: ${req.authnRequest.acsUrl}`;
            log.warn(message, { authnRequest: req.authnRequest });
            return callback(new Error(message));
          }
        }

        return callback(null, url);
      }

      const message = `Unrecognized service provider [${options.issuer}]`;
      logger.warn(message, { options });
      return callback(new Error(message));
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
  };

  self.spOptions = serviceProviderOptions;

  return self;
};

IdentityProvider.prototype.parseSignInRequest = function (req, callback) {
  const self = this;
  const options = {};

  // Look for a current user
  if (req.isAuthenticated()) {
    options.username = req.user.id;
  }

  // Look for a URL-based SSO request
  options.issuer = (req.query || {}).sp || (req.body || {}).sp;

  // Look for relay state
  options.relayState = (req.query || {}).relayState || (req.body || {}).RelayState;

  // Look for other options that may come through in a redirect after login
  options.id = (req.query || {}).id || (req.body || {}).id;
  options.destination = (req.query || {}).destination || (req.body || {}).destination;
  options.acsUrl = (req.query || {}).acsUrl || (req.body || {}).acsUrl;

  // Look for a SAML Request
  samlp.parseRequest(req, function(err, data) {
    if (err) {
      const message = 'Error parsing SAML Authentication Request';
      log.warn(message, {error: err});
      return callback(new Error(message));
    }

    if (data) {
      // If information has been provided twice, ensure they match
      if (options.issuer && data.issuer && data.issuer !== options.issuer) {
        const message = 'Service provider requested in URL does not match issuer of SAML request'
        log.warn(message, {
          requestedServiceProviderId: options.issuer,
          SAMLRequest: data
        });
        return callback(new Error(message));
      }

      options.id = data.id;
      options.issuer = options.issuer || data.issuer;
      options.destination = data.destination;
      options.acsUrl = data.assertionConsumerServiceURL;
      options.forceAuthn = (data.forceAuthn === 'true');
    }

    const spOptions = self.spOptions[options.issuer];

    if (!spOptions) {
      const message = `Unrecognized service provider [${options.issuer}]`;
      logger.warn(message, { options });
      return callback(new Error(message));
    }

    let url = spOptions.recipient;

    if (options.acsUrl && options.acsUrl !== spOptions.recipient) {
      if (spOptions.acceptedAcsUrls
        && spOptions.acceptedAcsUrls.includes(options.acsUrl)) {
        url = options.acsUrl;
      } else {
        const message = `Unacceptable ACS URL received in authentication request: [${req.authnRequest.acsUrl}]`;
        log.warn(message, { options });
        return callback(new Error(message));
      }
    }
    options.acsUrl = url;

    logger.info('Parsed sign-in request', { options });

    return callback(null, options);
  });
}

IdentityProvider.prototype.signIn = function (options) {
  const authOptions = Object.assign({}, this.options);
  
  authOptions.id = options.id;
  authOptions.audience = options.issuer;
  authOptions.inResponseTo = options.id;
  authOptions.destination = options.destination;
  authOptions.recipient = options.acsUrl;
  authOptions.allowRequestAcsUrl = this.spOptions[options.issuer].allowRequestAcsUrl;
  authOptions.signingCert = this.spOptions[options.issuer].signingCert;
  authOptions.digestAlgorithm = this.spOptions[options.issuer].digestAlgorithm;
  authOptions.acsUrl = options.acsUrl;
  authOptions.forceAuthn = options.forceAuthn;
  authOptions.RelayState = options.relayState;

  const loggedOptions = Object.assign({}, authOptions);
  if (loggedOptions.key) {
    loggedOptions.key = '-----REDACTED-----';
  }
  logger.info('Processing SAML-P authentication request', { loggedOptions  });

  // Copy function-based options
  authOptions.getUserFromRequest = this.options.getUserFromRequest;
  authOptions.getPostURL = this.options.getPostURL;
  authOptions.transformAssertion = this.options.transformAssertion;
  authOptions.responseHandler = this.options.responseHandler;

  return samlp.auth(authOptions);
};

IdentityProvider.prototype.renderMetadata = function () {
  return samlp.metadata(this.idpOptions);
};

exports = module.exports = IdentityProvider;
