/*!
 * Consumer is the core component of the Faithlife OAuth integration. It is
 * responsible for containing all application- and environment-specific
 * knowledge required to connect to and authenticate with the Faithlife
 * OAuth provider.
 */
var querystring = require('querystring');
var mach = require('mach');
var rest = require('rest');
var restMime = require('rest/interceptor/mime');
var restError = require('rest/interceptor/errorCode');

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

  this.token = options.token || process.env.FAITHLIFE_CONSUMER_TOKEN || null;
  this.secret = options.secret || process.env.FAITHLIFE_CONSUMER_SECRET || null;
  this.signatureMethod = 'PLAINTEXT';
  this.version = '1.0';

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

  var params = {
    oauth_consumer_key: this.token,
    oauth_signature: [this.secret, options.oauth_token_secret].join('%26'),
    oauth_signature_method: 'PLAINTEXT',
    oauth_version: '1.0'
  };

  ['oauth_callback', 'oauth_verifier', 'oauth_token'].forEach(function (key) {
    if (options[key]) {
      params[key] = options[key];
    }
  });

  return 'OAuth ' + Object.keys(params).map(function (key) {
    return key + '="' + params[key] + '"';
  }).join(', ');
};

/**
 * Generates a Mach-compatible subapp that should be mounted at the specified
 * `location`. When in doubt, use `mount` instead.
 */
FaithlifeOAuthConsumer.prototype.generateSubapp = function generateSubapp(location) {
  var self = this;

  function subapp(app) {
    // Require the `params` middleware for parsing bodies and query strings.
    // A no-op if `params` is already in use.
    app.use(mach.params);

    // Simple middleware to ensure `session` middleware is available before
    // continuing on to make OAuth requests.
    app.use(function (app) {
      return function (request) {
        if (!request.session) {
          throw new Error('Missing session middleware. Please install `mach.session` or similar to use Faithlife OAuth.');
        }

        return request.call(app);
      };
    });

    // The initial route a client should hit to view a sign-in page and
    // acquire a token. It's recommended to use an anchor (`a`) tag to
    // integrate this route, as it will populate the Referer header for you.
    app.get('/login', function (request) {
      return self.request({
        method: 'POST',
        path: 'https://auth.logos.com/oauth/v1/temporarytoken',
        headers: {
          Authorization: self.generateAuthHeader({
            // TODO(schoon) - Use HTTP(S) based on environment.
            oauth_callback: 'http://' + request.headers.host + location + '/verify'
          })
        }
      })
        .then(function (response) {
          request.session.oauth_token_secret = response.entity.oauth_token_secret;
          request.session.original_url = request.headers.referer || request.params.original_url;
          return mach.redirect('https://auth.logos.com/oauth/v1/authorize?' + querystring.stringify(response.entity));
        });
    });

    // The secondary route used to acquire the actual access token and secret.
    // Clients should _not_ hit this route directly. Use `/login` instead.
    app.get('/verify', function (request) {
      return self.request({
        method: 'POST',
        path: 'https://auth.logos.com/oauth/v1/accesstoken',
        headers: {
          Authorization: self.generateAuthHeader({
            oauth_token_secret: request.session.oauth_token_secret,
            oauth_token: request.params.oauth_token,
            oauth_verifier: request.params.oauth_verifier
          })
        }
      })
        .then(function (response) {
          var original_url = request.session.original_url;

          // We're already in dictionary mode, so delete is okay.
          delete request.session.original_url;

          request.session.oauth_token = response.entity.oauth_token;
          request.session.oauth_token_secret = response.entity.oauth_token_secret;

          // TODO(schoon) - Preserve the original Referer header?
          return mach.back(request, original_url);
        });
    });
  }

  return subapp;
};

/**
 * Mounts a subapp on `app` at the specified `location`.
 */
FaithlifeOAuthConsumer.prototype.mount = function mount(app, location) {
  return app.map(location, this.generateSubapp(location));
};

/*!
 * Export `FaithlifeOAuthConsumer`.
 */
module.exports = FaithlifeOAuthConsumer;
