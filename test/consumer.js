var assert = require('assert');
var mach = require('mach');
var lib = require('../lib');
var TOKEN = '0FAD08AE080463B64E60A2347415A3BC31FAC689';
var SECRET = 'E119997C9F524E9E8BD22D9B6EC4FCABD254518D';
var consumer = lib.createConsumer({
  token: TOKEN,
  secret: SECRET
});

/**
 * The Authorization header
 */
var header = consumer.generateAuthHeader();

// 1. Should exist.
assert.ok(header, 'Failed to generate header.');

// 2. Should be prefixed correctly.
assert.ok(RegExp('^OAuth').test(header), 'Missing prefix.');

// 3. Should contain the consumer token.
assert.ok(RegExp('oauth_consumer_key="' + TOKEN + '"').test(header), 'Missing consumer token.');

// 4. Should contain the consumer secret.
assert.ok(RegExp('oauth_signature="' + SECRET + '%26"').test(header), 'Missing consumer secret.');

// 5. Should specify the proper signature method.
assert.ok(RegExp('oauth_signature_method="PLAINTEXT"').test(header), 'Invalid signature method.');

// 6. Should specify the proper OAuth version.
assert.ok(RegExp('oauth_version="1.0"').test(header), 'Invalid OAuth version.');

/**
 * The Mach subapp
 */
var app = mach.stack();
app.use(mach.session, {
  secret: 'test',
  store: mach.session.MemoryStore()
});
consumer.mount(app, '/oauth');
var server = mach.serve(app, process.env.PORT || 22222);

/**
 * GET /login
 */
var response = consumer.request({
  method: 'GET',
  path: 'http://127.0.0.1:22222/oauth/login'
})
  .then(function (response) {
    // 1. Should redirect the user.
    assert.ok(
      ['302', '307'].indexOf(response.status.code.toString()) !== -1,
      'Not redirected.'
    );

    // 2. Should provide a new Location.
    assert.ok(response.headers.Location, 'Missing Location header.');

    // 3. Should redirect to the right auth.logos Location.
    assert.ok(RegExp('^https://auth.logos.com/oauth/v1/authorize').test(response.headers.Location), 'Invalid Location header.');

    // 4. Should redirect with a temporary access token query parameter.
    assert.ok(RegExp('oauth_token=').test(response.headers.Location), 'Location header missing access token parameter.');

    // 5. Should redirect with a temporary access secret query parameter.
    assert.ok(RegExp('oauth_token_secret=').test(response.headers.Location), 'Location header missing access secret parameter.');
  })
  .then(function () {
    server.close();
  })
  .done();

/**
 * GET /verify
 */
// TODO(schoon) - Automate the sign-in form submission and test /verify.
