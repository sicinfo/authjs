/**
 * @module authjs
 * @author moreira
 */
'use strict';

const jwt = require('jsonwebtoken');
const { Unauthorized } = require('http-errors');

const Authorization = 'authorization';
const Bearer = 'Bearer';
const JwtSecret = process.env.JWT_SECRET || `${process.env.username}${process.env.HOSTNAME}`
const expiresIn = 60 * 60; // 1 hora

const UTF8 = 'utf8';
const BASE64 = 'base64';

/**
 * @arg {Payload} payload
 * @arg {SignOptions} options
 * @this {SignThis}
 */
const _sign = function (payload, options = {}) {
  return `${this.Bearer || Bearer} ${jwt.sign(payload, this.secret || JwtSecret, options)}`
}

const Auth = class {

  /**
   * @param {AuthorizationType=} authorization
   * @param {boolean=} required
   * @return {Promise<Payload|undefined>}
   * @this {SignThis}
   */
  static validate(authorization, required) {
    const [bearer, token] = authorization?.split(' ') || [];

    return new Promise((resolve, reject) => {

      if (!bearer || bearer !== (this.Bearer || Bearer) || !token)
        reject(required ? new Unauthorized() : undefined)
      else
        jwt.verify(token, this.secret || JwtSecret, {}, (err, payload) => {
          if (err) reject(required ? new Unauthorized(err.message) : undefined) 
          else resolve('string' === typeof payload ? { payload } : payload)
        });
    });
  }

  /**
 * @param {Payload} payload
 * @param {SignOptions} options
 * @this {SignThis}
 */
  static create(payload = {}, options = {}) {
    if (undefined === options.expiresIn) options.expiresIn = expiresIn;
    if (undefined === payload.stp) payload.stp = 1 * /** @type { number } */ (options.expiresIn) || 0;
    if (undefined === payload.cnt) payload.cnt = 0;
    return _sign.call(this, payload, options);
  }

  /** 
   * @param {Payload} payload
   * @this {SignThis}
   */
  static renew(payload = {}) {
    payload.exp = (Date.now() / 1000 | 0) + (payload.stp || 0)
    payload.cnt = 1 + (payload.cnt || 0)
    return _sign.call(this, payload);
  }

  static btoa(/** @type {string} */ arg) {
    return Buffer.from(arg, UTF8).toString(BASE64)
  }
  
  static atob(/** @type {string} */ arg) {
    return Buffer.from(arg, BASE64).toString(UTF8)
  }

  /** @this {SignThis} */
  static get secret() { return this.secret || JwtSecret }

  /** @this {SignThis} */
  static get Bearer() { return this.Bearer || Bearer }

  static get Authorization() { return Authorization }
}

module.exports = Auth