'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

var _url = require('url');

var _url2 = _interopRequireDefault(_url);

var _crypto = require('crypto');

var _crypto2 = _interopRequireDefault(_crypto);

var _passportOauth = require('passport-oauth');

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

function _possibleConstructorReturn(self, call) { if (!self) { throw new ReferenceError("this hasn't been initialised - super() hasn't been called"); } return call && (typeof call === "object" || typeof call === "function") ? call : self; }

function _inherits(subClass, superClass) { if (typeof superClass !== "function" && superClass !== null) { throw new TypeError("Super expression must either be null or a function, not " + typeof superClass); } subClass.prototype = Object.create(superClass && superClass.prototype, { constructor: { value: subClass, enumerable: false, writable: true, configurable: true } }); if (superClass) Object.setPrototypeOf ? Object.setPrototypeOf(subClass, superClass) : subClass.__proto__ = superClass; }

/**
 * `FacebookTokenStrategy` constructor.
 *
 * The Facebook authentication strategy authenticates requests by delegating to
 * Facebook using the OAuth 2.0 protocol.
 *
 * Applications must supply a `verify` callback which accepts an `accessToken`,
 * `refreshToken` and service-specific `profile`, and then calls the `done`
 * callback supplying a `user`, which should be set to `false` if the
 * credentials are not valid.  If an exception occurred, `error` should be set.
 *
 * @param {Object} options
 * @param {Function} verify
 * @example
 * passport.use(new FacebookTokenStrategy({
 *   clientID: '123456789',
 *   clientSecret: 'shhh-its-a-secret'
 * }), (accessToken, refreshToken, profile, done) => {
 *   User.findOrCreate({facebookId: profile.id}, done);
 * });
 */
var FacebookTokenStrategy = function (_OAuth2Strategy) {
  _inherits(FacebookTokenStrategy, _OAuth2Strategy);

  function FacebookTokenStrategy(_options, _verify) {
    _classCallCheck(this, FacebookTokenStrategy);

    var options = _options || {};
    var verify = _verify;
    var _fbGraphVersion = options.fbGraphVersion || 'v2.6';

    options.authorizationURL = options.authorizationURL || 'https://www.facebook.com/' + _fbGraphVersion + '/dialog/oauth';
    options.tokenURL = options.tokenURL || 'https://graph.facebook.com/' + _fbGraphVersion + '/oauth/access_token';

    var _this = _possibleConstructorReturn(this, (FacebookTokenStrategy.__proto__ || Object.getPrototypeOf(FacebookTokenStrategy)).call(this, options, verify));

    _this.name = 'facebook-token';
    _this._accessTokenField = options.accessTokenField || 'access_token';
    _this._refreshTokenField = options.refreshTokenField || 'refresh_token';
    _this._profileURL = options.profileURL || 'https://graph.facebook.com/' + _fbGraphVersion + '/me';
    _this._profileFields = options.profileFields || ['id', 'displayName', 'name', 'emails'];
    _this._profileImage = options.profileImage || {};
    _this._clientSecret = options.clientSecret;
    _this._clientID = options.clientID;
    _this._enableProof = typeof options.enableProof === 'boolean' ? options.enableProof : true;
    _this._passReqToCallback = options.passReqToCallback;
    _this._oauth2.useAuthorizationHeaderforGET(false);
    _this._fbGraphVersion = _fbGraphVersion;
    _this.tokenURL = options.tokenURL;
    _this._getLongLivedToken = options.getLongLivedToken || false;
    _this._storeLongLiveToken = options.storeLongLiveToken || false;
    return _this;
  }

  /**
   * Authenticate request by delegating to a service provider using OAuth 2.0.
   * @param {Object} req
   * @param {Object} options
   */


  _createClass(FacebookTokenStrategy, [{
    key: 'authenticate',
    value: function authenticate(req, options) {
      var _this2 = this;

      var accessToken = this.lookup(req, this._accessTokenField);
      var refreshToken = this.lookup(req, this._refreshTokenField);
      var self = this;
      if (!accessToken) return this.fail({ message: 'You should provide ' + this._accessTokenField });

      this._loadUserProfile(accessToken, function (error, profile) {
        if (error) return _this2.error(error);

        var verified = function verified(error, user, info) {
          if (error) return _this2.error(error);
          if (!user) return _this2.fail(info);

          return _this2.success(user, info);
        };
        var passCallback = function passCallback(req, accessToken, refreshToken, profile) {
          if (self._storeLongLiveToken) {
            accessToken = req.body.longLivedToken;
          }

          if (self._passReqToCallback) {
            self._verify(req, accessToken, refreshToken, profile, verified);
          } else {
            self._verify(accessToken, refreshToken, profile, verified);
          }
        };
        if (self._getLongLivedToken) {
          self._getLLT(accessToken, function (err, longLivedToken, expires) {
            if (err) {
              self.error(err);
              return;
            }

            req.body.longLivedToken = longLivedToken;
            if (expires !== null) {
              req.body.longLivedTokenExpires = expires;
            }
            passCallback(req, accessToken, refreshToken, profile);
          });
        } else {
          passCallback(req, accessToken, refreshToken, profile);
        }
      });
    }

    /**
     * Retrieve user profile from Facebook.
     *
     * This function constructs a normalized profile, with the following properties:
     *
     *   - `provider`         always set to `facebook`
     *   - `id`               the user's Facebook ID
     *   - `username`         the user's Facebook username
     *   - `displayName`      the user's full name
     *   - `name.familyName`  the user's last name
     *   - `name.givenName`   the user's first name
     *   - `name.middleName`  the user's middle name
     *   - `gender`           the user's gender: `male` or `female`
     *   - `profileUrl`       the URL of the profile for the user on Facebook
     *   - `emails`           the proxied or contact email address granted by the user
     *
     * @param {String} accessToken
     * @param {Function} done
     */

  }, {
    key: 'userProfile',
    value: function userProfile(accessToken, done) {
      var _this3 = this;

      var profileURL = _url2.default.parse(this._profileURL);

      // For further details, refer to https://developers.facebook.com/docs/reference/api/securing-graph-api/
      if (this._enableProof) {
        var proof = _crypto2.default.createHmac('sha256', this._clientSecret).update(accessToken).digest('hex');
        profileURL.search = (profileURL.search ? profileURL.search + '&' : '') + 'appsecret_proof=' + encodeURIComponent(proof);
      }

      // Parse profile fields
      if (this._profileFields) {
        var fields = FacebookTokenStrategy.convertProfileFields(this._profileFields);
        profileURL.search = (profileURL.search ? profileURL.search + '&' : '') + 'fields=' + fields;
      }

      profileURL = _url2.default.format(profileURL);

      this._oauth2.get(profileURL, accessToken, function (error, body, res) {
        if (error) return done(new _passportOauth.InternalOAuthError('Failed to fetch user profile', error));

        try {
          var json = JSON.parse(body);

          // Get image URL based on profileImage options
          var imageUrl = _url2.default.parse('https://graph.facebook.com/' + _this3._fbGraphVersion + '/' + json.id + '/picture');
          if (_this3._profileImage.width) imageUrl.search = 'width=' + _this3._profileImage.width;
          if (_this3._profileImage.height) imageUrl.search = (imageUrl.search ? imageUrl.search + '&' : '') + 'height=' + _this3._profileImage.height;
          imageUrl.search = '' + (imageUrl.search ? imageUrl.search : 'type=large');
          imageUrl = _url2.default.format(imageUrl);

          var profile = {
            provider: 'facebook',
            id: json.id,
            displayName: json.name || '',
            name: {
              familyName: json.last_name || '',
              givenName: json.first_name || '',
              middleName: json.middle_name || ''
            },
            gender: json.gender || '',
            emails: [{
              value: json.email || ''
            }],
            photos: [{
              value: imageUrl
            }],
            _raw: body,
            _json: json
          };

          done(null, profile);
        } catch (e) {
          done(e);
        }
      });
    }

    /**
     * Parses an OAuth2 RFC6750 bearer authorization token, this method additionally is RFC 2616 compliant and respects
     * case insensitive headers.
     *
     * @param {Object} req http request object
     * @returns {String} value for field within body, query, or headers
     */

  }, {
    key: 'parseOAuth2Token',
    value: function parseOAuth2Token(req) {
      var OAuth2AuthorizationField = 'Authorization';
      var headerValue = req.headers && (req.headers[OAuth2AuthorizationField] || req.headers[OAuth2AuthorizationField.toLowerCase()]);

      return headerValue && function () {
        var bearerRE = /Bearer\ (.*)/;
        var match = bearerRE.exec(headerValue);
        return match && match[1];
      }();
    }

    /**
     * Performs a lookup of the param field within the request, this method handles searhing the body, query, and header.
     * Additionally this method is RFC 2616 compliant and allows for case insensitive headers. This method additionally will
     * delegate outwards to the OAuth2Token parser to validate whether a OAuth2 bearer token has been provided.
     *
     * @param {Object} req http request object
     * @param {String} field
     * @returns {String} value for field within body, query, or headers
     */

  }, {
    key: 'lookup',
    value: function lookup(req, field) {
      return req.body && req.body[field] || req.query && req.query[field] || req.headers && (req.headers[field] || req.headers[field.toLowerCase()]) || this.parseOAuth2Token(req);
    }

    /**
     * Converts array of profile fields to string
     * @param {Array} _profileFields Profile fields i.e. ['id', 'email']
     * @returns {String}
     */

  }, {
    key: '_getLLT',

    /**
     * Attempts to get a Long-Lived Token from Facebook.
     * Requires a valid clientID (AppID), clientSecret (AppSecret) and accessToken
     *
     * @param {String} accessToken
     * @param {Function} done
     * @api private
     */
    value: function _getLLT(accessToken, done) {
      var url = this.tokenURL + "?" + "grant_type=fb_exchange_token" + "&" + "client_id=" + this._clientID + "&" + "client_secret=" + this._clientSecret + "&" + "fb_exchange_token=" + accessToken;
      url = _url2.default.parse(url);

      if (this._enableProof) {
        // Secure API call by adding proof of the app secret.  This is required when
        // the "Require AppSecret Proof for Server API calls" setting has been
        // enabled.  The proof is a SHA256 hash of the access token, using the app
        // secret as the key.
        //
        // For further details, refer to:
        // https://developers.facebook.com/docs/reference/api/securing-graph-api/
        var proof = _crypto2.default.createHmac('sha256', this._clientSecret).update(accessToken).digest('hex');
        url.search = (url.search ? url.search + '&' : '') + 'appsecret_proof=' + encodeURIComponent(proof);
      }
      url = _url2.default.format(url);
      this._oauth2.getProtectedResource(url, accessToken, function (err, body, res) {
        if (err) {
          return done(new _passportOauth.InternalOAuthError('failed to get long-lived token', err));
        }
        try {
          body = JSON.parse(body);
          if (typeof body.access_token === "undefined") {
            return done(new _passportOauth.InternalOAuthError('facebook was unable to provide a long-lived token'));
          }
          if (typeof body.expires_in === "undefined") {
            body.expires_in = null;
          }
          return done(null, body.access_token, body.expires_in);
        } catch (e) {
          done(e);
        }
      });
    }
  }], [{
    key: 'convertProfileFields',
    value: function convertProfileFields(_profileFields) {
      var profileFields = _profileFields || [];
      var map = {
        'id': 'id',
        'displayName': 'name',
        'name': ['last_name', 'first_name', 'middle_name'],
        'gender': 'gender',
        'profileUrl': 'link',
        'emails': 'email',
        'photos': 'picture'
      };

      return profileFields.reduce(function (acc, field) {
        return acc.concat(map[field] || field);
      }, []).join(',');
    }
  }]);

  return FacebookTokenStrategy;
}(_passportOauth.OAuth2Strategy);

exports.default = FacebookTokenStrategy;
module.exports = exports['default'];