var querystring = require('querystring');
var mach = require('mach');
var rest = require('rest');
var restMime = require('rest/interceptor/mime');
var restError = require('rest/interceptor/errorCode');
var makeRequest = rest.wrap(restMime).wrap(restError);

var CONSUMER_TOKEN = process.env.CONSUMER_TOKEN;
var CONSUMER_SECRET = process.env.CONSUMER_SECRET;

function generateAuthorization(data) {
  var options = {
    oauth_consumer_key: CONSUMER_TOKEN,
    oauth_signature: [CONSUMER_SECRET, data.oauth_token_secret].join('%26'),
    oauth_signature_method: 'PLAINTEXT',
    oauth_version: '1.0'
  };

  ['oauth_callback', 'oauth_verifier', 'oauth_token'].forEach(function (key) {
    if (data[key]) {
      options[key] = data[key];
    }
  });

  return 'OAuth ' + Object.keys(options).map(function (key) {
    return key + '="' + options[key] + '"';
  }).join(', ');
}

function generateSubapp(location) {
  return function subapp(app) {
    app.use(mach.session, 'INSERT SECRET JOKE HERE');
    app.use(mach.params);

    app.get('/login', function (request) {
      return makeRequest({
        method: 'POST',
        path: 'https://auth.logos.com/oauth/v1/temporarytoken',
        headers: {
          Authorization: generateAuthorization({
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

    app.get('/verify', function (request) {
      return makeRequest({
        method: 'POST',
        path: 'https://auth.logos.com/oauth/v1/accesstoken',
        headers: {
          Authorization: generateAuthorization({
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
  };
}

function mount(app, location) {
  app.map(location, generateSubapp(location));
}

module.exports = {
  mount: mount
};
