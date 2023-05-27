/**
 * @typedef { import('jsonwebtoken').JwtPayload & SignArgsOptions } Payload 
 * @typedef { import('jsonwebtoken').SignOptions} SignOptions
 * @typedef {{Bearer?:string,secret?:string}} SignThis
 * @typedef {string} AuthorizationType
 */ /**
 * @typedef SignArgsOptions
 * @property { number= } stp
 * @property { number= } cnt
 * @property { string= } name
 * @property { string= } api
 */