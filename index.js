'use strict';


var normalizeUrl = require('normalizeurl');
var x509 = require('x509');
var request = require('request');
var crypto = require('crypto');
var StaleLruCache = require('stale-lru-cache');
var configExtend = require('config-extend');


const DEFAULT_OPTIONS = {
	urlPattern: new RegExp('^https://s3\.amazonaws\.com(:443)?\/echo.api\/'),
	cache: {
		maxSize: 100,
		maxAge: 600,
		staleWhileRevalidate: 86400
	}
}


/**
 * Verify requests coming from Amazon Alexa
 *
 * @class VerifyAlexaSkillRequest
 *
 * @param options {Object}
 *   @param {RegExp} [options.urlPattern=RegExp('^https://s3\.amazonaws\.com(:443)?\/echo.api\/')] pattern used to verify signature URL
 *   @param {Object} options.cache
 *     @param {Number} [options.cache.maxAge=100] maximum age of cache
 *     @param {Number} [options.cache.staleWhileRevalidate=86400] maximum age of a staled cached certificate that can still be used
 *   @param applicationId {String|String[]} ID or array of IDs for the Alexa application
 **/

class VerifyAlexaSkillRequest {

	constructor(options) {
		this.options = configExtend(DEFAULT_OPTIONS, options);

		// Cache for SignatureCertChain
		this.cache = new StaleLruCache({
			maxSize: this.options.cache.maxSize,
			maxAge: this.options.cache.maxAge,
			staleWhileRevalidate: this.options.cache.staleWhileRevalidate,
			revalidate: this._fetchSignatureCertChain
		});
	}


	/**
	 * Fetch certificate for cache
	 *
     * @private
     */

	_fetchSignatureCertChain(key, cb) {
		request(key, function (err, res, data) {
			if (err) {
				cb(err)
			}
			else if (res.statusCode != 200) {
				cb(new Error('Invalid status code: ' + res.statusCode));
			}
			else {
				cb(null, x509.parseCert(data));
			}
		});
	}


	/**
	 * Verify that an Alexa skill request is valid.
	 *
	 * @param {String} url
	 * @param {String} signature
	 * @param {Object} body request body
	 * @param {Function} cb callback
	 **/

	verify(url, signature, body, cb) {
		let date = new Date();

		// Basic request validation
		if (!body || !body.request || !body.request.type) {
			return cb(new Error('Invalid body'));
		}

		// Validate the application ID if we have it
		if (this.options.applicationId) {
			if (!body.session || !body.session.application || !body.session.application.applicationId) {
				return cb(new Error('Missing session.application.applicationId'));
			}

			if ((Array.isArray(this.options.applicationId) && this.options.applicationId.indexOf(body.session.application.applicationId) === -1) ||
				this.options.applicationId !== body.session.application.applicationId)  {

				return cb(new Error('Invalid session.application.applicationId;'))
			}
		}

		let timestamp = new Date(body.request.timestamp);

		// Check timestamp is within a reasonable range
		// Note: Server clock should be synced using NTP
		if(Math.abs(date - timestamp) / 1000 > 150) {
			return cb(new Error('Invalid timestamp'));
		}
		// Validate certificate url
		else if(!this.options.urlPattern.test(url)) {
			return cb(new Error('Invalid SignatureCertChainUrl'));
		}
		else {
			// Get cert from cache
			this.cache.wrap(url, this._fetchSignatureCertChain, (err, data) => {
				if (err) return cb(err);

				let valid = false;
				let cert = x509.parseCert(data);

				if (cert.notBefore <= date && cert.notAfter >= date) {
					var san = cert.extensions.subjectAlternativeName;

					if(san === 'DNS:echo-api.amazon.com') {
						var publicKey = cert.publicKey.n,
						verifier = crypto.createVerify('SHA1');

						// validate request body
						verifier.update(JSON.stringify(body));
						valid = verifier.verify(data, signature, 'base64');
					}

				}

				if (valid) {
					cb();
				}
				else {
					cb(new Error('Invalid signature'));
				}
			});
		}

	}
}





module.exports = VerifyAlexaSkillRequest;
