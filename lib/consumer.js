/*!
 * Consumer is the core component of the Faithlife OAuth integration. It is
 * responsible for containing all application- and environment-specific
 * knowledge required to connect to and authenticate with the Faithlife
 * OAuth provider.
 */
var querystring = require('querystring');
var express = require('express');
var rest = require('rest');
var restMime = require('rest/interceptor/mime');
var restError = require('rest/interceptor/errorCode');
var utils = require('./utils');

/**
 * Creates a new instance of FaithlifeOAuthConsumer with the provided `options`.
 * The available options are:
 *
 *  - `token`: The OAuth consumer token to use. Defaults to the
 *    `FAITHLIFE_CONSUMER_TOKEN` environment variable.
 *  - `secret`: The OAuth consumer secret to use. Defaults to the
 *    `FAITHLIFE_CONSUMER_SECRET` environment variable.
 */
function FaithlifeOAuthConsumer(options) {
  if (!(this instanceof FaithlifeOAuthConsumer)) {
    return new FaithlifeOAuthConsumer(options);
  }

  options = options || {};

  this.rootUrl = options.rootUrl || 'https://auth.logos.com/oauth';
  this.token = options.token || process.env.FAITHLIFE_CONSUMER_TOKEN || null;
  this.secret = options.secret || process.env.FAITHLIFE_CONSUMER_SECRET || null;

  this.request = rest.wrap(restMime).wrap(restError);
}
FaithlifeOAuthConsumer.createConsumer = FaithlifeOAuthConsumer;

/**
 * Generates an `Authorization` header based on the Consumer's token, secret,
 * and the supplied `options`. All `options` will be formatted as a part
 * of the header, but `oauth_token_secret` is expected for authenticated
 * sessions.
 */
FaithlifeOAuthConsumer.prototype.generateAuthHeader = function generateAuthHeader(options) {
  options = options || {};

  var key = [this.secret, options.oauth_token_secret].join('&');
  var params = {
    oauth_consumer_key: this.token,
    oauth_signature_method: options.signatureMethod || 'PLAINTEXT',
    oauth_version: '1.0',
    oauth_timestamp: Math.floor(Date.now() / 1000),
    oauth_nonce: Math.random().toString(26).slice(2)
  };

  ['oauth_callback', 'oauth_verifier', 'oauth_token'].forEach(function (key) {
    if (options[key]) {
      params[key] = options[key];
    }
  });

  Object.keys(options.params || {}).forEach(function (key) {
    params[key] = options.params[key];
  });

  switch (params.oauth_signature_method) {
    case 'HMAC-SHA1':
      params.oauth_signature = encodeURIComponent(utils.generateHmacSignature(options.url, params, key));
      break;
    case 'PLAINTEXT':
      params.oauth_signature = encodeURIComponent(key);
      break;
  }

  return 'OAuth ' + Object.keys(params).map(function (key) {
    return key + '="' + params[key] + '"';
  }).join(', ');
};

/**
 * Generates an Express-compatible subapp that should be mounted at the
 * specified `location`. When in doubt, use `mount` instead.
 */
FaithlifeOAuthConsumer.prototype.generateSubapp = function generateSubapp(location) {
  var self = this;
  var app = express();

  // Simple middleware to ensure `session` middleware is available before
  // continuing on to make OAuth requests.
  app.use(function (request, response, next) {
    if (!request.session) {
      return next(new Error('Missing session middleware. Please install `express-session` or similar to use Faithlife OAuth.'));
    }

    next();
  });

  // The initial route a client should hit to view a sign-in page and
  // acquire a token. It's recommended to use an anchor (`a`) tag to
  // integrate this route, as it will populate the Referer header for you.
  app.get('/signin', function (request, response, next) {
    self.request({
      method: 'POST',
      path: self.rootUrl + '/v1/temporarytoken',
      headers: {
        Authorization: self.generateAuthHeader({
          // TODO(schoon) - Use HTTP(S) based on environment.
          oauth_callback: 'http://' + request.header('host') + location + '/verify'
        })
      }
    })
      .then(function (data) {
        request.session.oauth_token_secret = data.entity.oauth_token_secret;
        request.session.original_url = request.header('referer') || request.param('original_url');

        response.redirect(302, self.rootUrl + '/v1/authorize?' + querystring.stringify(data.entity));
      })
      .then(null, next);
  });

  // The secondary route used to acquire the actual access token and secret.
  // Clients should _not_ hit this route directly. Use `/login` instead.
  app.get('/verify', function (request, response, next) {
    self.request({
      method: 'POST',
      path: self.rootUrl + '/v1/accesstoken',
      headers: {
        Authorization: self.generateAuthHeader({
          oauth_token_secret: request.session.oauth_token_secret,
          oauth_token: request.param('oauth_token'),
          oauth_verifier: request.param('oauth_verifier')
        })
      }
    })
      .then(function (data) {
        var original_url = request.session.original_url;

        // We're already in dictionary mode, so delete is okay.
        delete request.session.original_url;

        request.session.oauth_token = data.entity.oauth_token;
        request.session.oauth_token_secret = data.entity.oauth_token_secret;

        response.redirect(302, original_url || '/');
      }, function (data) {
        console.log('BRV:', data);
      })
      .then(null, next);
  });

  // This Single-Sign-On-specific route associates the received access token
  // and secret with the user's session within this application.
  app.post('/associate', function (request, response, next) {
    request.session.oauth_token = request.params.accessToken;
    request.session.oauth_token_secret = request.params.accessSecret;

    response.send(204);
  });

  return app;
};

/**
 * Mounts a subapp on `app` at the specified `location`.
 */
FaithlifeOAuthConsumer.prototype.mountRoutes = function mountRoutes(app, location) {
  return app.use(location, this.generateSubapp(location));
};

/**
 * Generates a Single-Sign-On request URL, which should be used as the `src`
 * attribute in a script tag after `methodName` has been defined.
 */
FaithlifeOAuthConsumer.prototype.getJsonpUrl = function getJsonpUrl(methodName) {
  var authHeader = this.generateAuthHeader({
    signatureMethod: 'HMAC-SHA1',
    url: this.rootUrl + '/v1/users/credentials',
    params: {
      jsonp: methodName
    }
  });

  return this.rootUrl + '/v1/users/credentials?jsonp=' + methodName + '&authorizationHeader=' + encodeURIComponent(authHeader);
};

/**
 * Returns Express-compatible middleware that adds an appropriate
 * `Authorization` header as `request.authorization`.
 */
FaithlifeOAuthConsumer.prototype.authorizationHandler = function authorizationHandler() {
  var self = this;

  return function addAuthHeader(request, response, next) {
    request.authorization = self.generateAuthHeader(request.session);

    console.log('AUTH:', request.authorization);

    next();
  };
};

/*!
 * Export `FaithlifeOAuthConsumer`.
 */
module.exports = FaithlifeOAuthConsumer;
