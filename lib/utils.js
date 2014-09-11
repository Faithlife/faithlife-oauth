var crypto = require('crypto');

function generateHmacSignature(url, params, key) {
  var hmac = crypto.createHmac('sha1', key);
  var base = [
    'GET',
    encodeURIComponent(url),
    encodeURIComponent(arrangeParameters(params))
  ].join('&');

  return hmac.update(base).digest('base64');
}

function arrangeParameters(params) {
  return Object
    .keys(params)
    .sort()
    .map(function (key) {
      return key + '=' + params[key];
    })
    .join('&');
}

module.exports = {
  generateHmacSignature: generateHmacSignature
};
