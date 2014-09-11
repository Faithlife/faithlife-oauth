var assert = require('assert');
var utils = require('../lib/utils');
var url = 'https://test.example.com/protected';
var TOKEN = 'test_token';
var SECRET = 'test_secret';
var params = {
  foo: 'bar',
  answer: 42,
  help: 'me'
};
var key = [SECRET, undefined].join('&');

assert.equal(
  utils.generateHmacSignature(url, params, key),
  'lybVmQePkKAH8rGAUXcNuyfj8UU=',
  'Generated invalid signature.'
);
