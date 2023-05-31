/**
 * @author moreira
 */ /**
 * @typedef { import('jsonwebtoken').JwtPayload & SignArgsOptions } Payload
 * @typedef { import('jsonwebtoken').SignOptions} SignOptions
 * @typedef {{Bearer?:string,secret?:string}} SignThis
 */ /**
 * @template [T=string]
 * @typedef {T} SignResult
 */ /**
 * @typedef SignArgsOptions
 * @property {number=} stp
 * @property {number=} cnt
 * @property {string=} name
 * @property {string=} api 
 */ /**
 * @template [T=string]
 * @typedef {(a?:T,b?:boolean)=>Promise<Payload|undefined>} validate
 */ /**
 * @template [T=string]
 * @typedef {T} Authorization
 */ /**
 * @typedef {(a:Payload,b?:SignOptions)=>SignResult} _sign
 * @typedef {(a:Payload,b:SignOptions)=>SignResult} create
 * @typedef {(a:Payload)=>SignResult} renew
 * @typedef {(a:string)=>string} btoa
 * @typedef {(a:string)=>string} atob
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
 * @type {_sign} 
 * @this {SignThis} 
 */
const _sign = function (payload, options = {}) {
  return `${this.Bearer || Bearer} ${jwt.sign(payload, this.secret || JwtSecret, options)}`
}

/** @module */
const Authjs = module.exports = class {

  /**
   * @type {validate}
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
   * @type {create}
   * @this {SignThis}
   */
  static create(payload = {}, options = {}) {
    if (undefined === options.expiresIn) options.expiresIn = expiresIn;
    if (undefined === payload.stp) payload.stp = 1 * /** @type { number } */ (options.expiresIn) || 0;
    if (undefined === payload.cnt) payload.cnt = 0;
    return _sign.call(this, payload, options);
  }

  /** 
   * @type {renew}
   * @this {SignThis}
   */
  static renew(payload = {}) {
    payload.exp = (Date.now() / 1000 | 0) + (payload.stp || 0)
    payload.cnt = 1 + (payload.cnt || 0)
    return _sign.call(this, payload);
  }

  /** @type {btoa} */
  static btoa(arg) {
    return Buffer.from(arg, UTF8).toString(BASE64)
  }
  
  /** @type {atob} */
  static atob(arg) {
    return Buffer.from(arg, BASE64).toString(UTF8)
  }

  /** @this {SignThis} */
  static get secret() { return this.secret || JwtSecret }

  /** @this {SignThis} */
  static get Bearer() { return this.Bearer || Bearer }

  /** @type{Authorization} */
  static get Authorization() { return Authorization }
}