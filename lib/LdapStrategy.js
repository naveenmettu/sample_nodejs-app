const util = require('util');
const Strategy = require('passport-strategy');
const ldap = require('ldapjs');
const logger = require('./logger');

class LdapStrategy extends Strategy {
  constructor(options, verify) {
    // TODO: Validate options

    super(options, verify)

    Strategy.call(this);

    this.name   = 'ldap';
    this.options = options;
    this.verify = verify;
  }

  authenticate(req, options) {
    var self = this;

    if (req.isAuthenticated()) {
      return self.success(req.user);
    }

    const username = (req.body ? req.body.username : null) || (req.query ? req.query.username : null);
    const password = (req.body ? req.body.password : null) || (req.query ? req.query.password : null);

    logger.debug(`Authenticating request; ${req.user ? '' : 'no '}user present; username ${username || 'not present'}`);

    if (!username || !password) {
      return this.fail('Must provide username and password', 400);
    }

    authenticate.call(self, username, password, function (err, user) {
      if (err) {
        let message = MESSAGES.DEFAULT;

        if (err.name === 'InvalidCredentialsError' || err.name === 'NoSuchObjectError' || (typeof err === 'string' && err.match(/no such user/i))) {
          if (err.message) {
            const ldapComment = err.message.match(/data ([0-9a-fA-F]*), v[0-9a-fA-F]*/);
            if (ldapComment && ldapComment[1] && MESSAGES[ldapComment[1]]){
              message = MESSAGES[ldapComment[1]];
            }
          }
        }
        if (err.name === 'ConstraintViolationError'){
          message = 'Exceeded password retry limit, account locked';
        }

        logger.debug(`Authentication failed for user ${username}: ${message}`);

        return self.fail(message);
      }

      if (!user) {
        logger.error(`Received no user for username ${username}`);
        return self.error(new Error('Did not receive user object'));
      }

      if (self.verify) {
        return self.verify(user, function (err, verifiedUser) {
          if (err) {
            logger.warn(`Failed during user profile verification for user:\n${user}\nError:\n${err}`);
            return self.fail('Unable to validate user profile');
          } else if(!user) {
            logger.error(`Received no verified user for username ${username}`);
            return self.error(new Error(`Did not receive user object from profile verification function for user:\n${user}`));
          }

          logger.info(`User ${username} successfully logged in and was verified`);
          return self.success(verifiedUser);
        });
      }

      // No verification needed
      logger.info(`User ${username} successfully logged in`);
      return self.success(user);
    });
  };
}

exports = module.exports = LdapStrategy;

// http://www-01.ibm.com/support/docview.wss?uid=swg21290631
const MESSAGES = {
  '530': 'Not Permitted to login at this time',
  '531': 'Not permited to logon at this workstation',
  '532': 'Password expired',
  '533': 'Account disabled',
  '534': 'Account disabled',
  '701': 'Account expired',
  '773': 'User must reset password',
  '775': 'User account locked',
  DEFAULT: 'Invalid username/password'
};

function authenticate(username, password, callback) {
  var self = this;
  const client = ldap.createClient({url: self.options.url});

  return client.bind(self.options.serviceAccountDn, self.options.serviceAccountPassword, function (err) {
    if (err) {
      logger.error(`Unable to bind LDAP client for ${self.options.serviceAccountDn} to ${self.options.url}`);
      return callback(err);
    }

    return search.call(self, client, username, function (err, user) {
      if (err) {
        return callback(err);
      }
      logger.debug(`Found user in directory: ${user.dn}`);
      return client.bind(user.dn.toString(), password, function (err) {
        try {
          client.unbind();
        } catch(err) {
          // Ignore any issues unbinding
        }

        if (err) {
          return callback(err);
        }

        return callback(null, user);
      });
    });
  });
}

/**
 * @param {string} username
 * @return {Promise} An object with the user details
 */
function search(client, username, callback) {
  var self = this;

  const options = {
    filter: `(sAMAccountName=${username})`,
    scope: 'sub'
  };

  logger.debug(`Searching for user with options ${JSON.stringify(options)} from ${self.options.searchBase}`);
  client.search(self.options.searchBase, options, function (err, search) {
    let user;

    if (err) {
      return callback(err);
    }

    search.on('searchEntry', function (entry) {
      user = entry.raw;
    });

    search.on('error', callback);

    search.on('end', function () {
      if (user) {
        callback(null, user);
      } else {
        logger.debug(`User ${username} not found`);
        callback(new Error('User not found'));
      }
    });
  });
}
