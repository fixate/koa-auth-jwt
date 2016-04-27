const jwt = require('jsonwebtoken');

module.exports = init;

function init(options) {
  const secret = options.secret;
  const header = options.header || 'X-Auth-Token';
  const expiryValidation = validateExpiry(options.expiresIn);

  return auth;

  function* auth(next){
    const token = this.request.get(header);
    const user = yield verifyToken(token, expiryValidation);

    if (!user){
      return this.status = 401;
    }

    this.state.user = user;

    yield next;
  }

  function verifyToken(token, validation) {
    return new Promise((resolve, reject) => {
      if (!token) return resolve({ error: 'Permission denied' });

      jwt.verify(token, secret, (err, decoded) => {
        if (err) {
          console.warn(err.stack);
          return resolve({ error: 'Permission denied' });
        }

        if (validation && !validation(decoded)) {
          console.warn('Invalid token');
          return resolve({ error: 'Permission denied' });
        }

        return resolve(decoded);
      });
    });
  }

  function validateExpiry(time) {
    return function expiryValidation(decodedToken) {
      if (!time) return true;

      const iat = +decodedToken.iat;
      if (!iat) return false;

      const now = Math.round(new Date().getTime() / 1000);
      return now <= iat + time;
    }
  }
}
