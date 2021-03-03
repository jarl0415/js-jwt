"use strict";
const util = require('util');
const Buffer = require('safe-buffer').Buffer;
const jwa = require('jwa');
const lodash_1 = require("lodash");
const tslib_1 = require("tslib");
const jsonwebtoken_1 = tslib_1.__importStar(require("jsonwebtoken"));

class jwt {
  /**
   * 构造函数
   * @param secret 牌的secret值
   * @param accessExp access token 过期时间
   * @param refreshExp refresh token 过期时间
   */
  constructor(secret, accessExp, refreshExp) {
      /**
       * access token 默认的过期时间
       */
      this.accessExp = 60 * 60; // 1h;
      /**
       * refresh token 默认的过期时间
       */
      this.refreshExp = 60 * 60 * 24 * 30 * 3; // 3 months
      secret && (this.secret = secret);
      refreshExp && (this.refreshExp = refreshExp);
      accessExp && (this.accessExp = accessExp);
  }

    /**
   * 颁发令牌
   * @param user 用户
   */
  getTokens(user) {
    const accessToken = this.createAccessToken(user.id);
    const refreshToken = this.createRefreshToken(user.id);
    return { accessToken, refreshToken };
  }

  /**
   * 生成access_token
   * @param identity 标识位
   */
  createAccessToken(identity) {
      if (!this.secret) {
          throw new Error('secret can not be empty');
      }
      let iat = Math.floor(Date.now() / 1000);
      let exp = iat + this.accessExp;
      return this.sign({
          exp,
          identity,
          scope: 'lin',
          type: 'access',
          iat: iat
      }, this.secret);
  }
  /**
   * 生成refresh_token
   * @param identity 标识位
   */
  createRefreshToken(identity) {
      if (!this.secret) {
          throw new Error('secret can not be empty');
      }
      let iat = Math.floor(Date.now() / 1000);
      let exp = iat + this.refreshExp;
      return this.sign({
          exp: exp,
          identity: identity,
          scope: 'lin',
          type: 'refresh',
          iat: iat
      }, this.secret);
  }
  /**
   * verifyToken 验证token
   * 若过期，抛出ExpiredTokenException
   * 若失效，抛出InvalidTokenException
   *
   * @param token 令牌
   */
  verifyToken(token, type = 'access') {
      if (!this.secret) {
          throw new Error('secret can not be empty');
      }
      // NotBeforeError
      // TokenExpiredError
      let decode;
      try {
          decode = jsonwebtoken_1.default.verify(token, this.secret);
      }
      catch (error) {
          if (error instanceof jsonwebtoken_1.TokenExpiredError) {
              if (type === 'access') {
                  throw new Error('access token 过期');
              }
              else if (type === 'refresh') {
                  throw new Error('refresh token 过期');
              }
              else {
                  throw new Error('验证失败');
              }
          }
          else {
              if (type === 'access') {
                  throw new Error('access token 损坏');
              }
              else if (type === 'refresh') {
                  throw new Error('refresh token 损坏');
              }
              else {
                throw new Error('验证失败');
              }
          }
      }
      return decode;
  }

  sign(payload, secretOrPrivateKey) {
  
    var header = {
      alg: 'HS256',
      typ: 'JWT'
    };
  
    if (!secretOrPrivateKey) {
      throw new Error('secretOrPrivateKey must have a value');
    } 
    const encoding = 'utf8';
    var encodedHeader = this.base64url(JSON.stringify(header), 'binary');
    
    var encodedPayload = this.base64url(JSON.stringify(payload), encoding);
    
    var securedInput = util.format('%s.%s', encodedHeader, encodedPayload);
    var algo = jwa(header.alg);
    var signature = algo.sign(securedInput, secretOrPrivateKey);
    return util.format('%s.%s', securedInput, signature);
  }

    /**
   * 解析请求头
   * @param ctx koa 的context
   * @param type 令牌的类型
   */
  parseHeader(authorization, type = 'access') {
    
    const parts = authorization.split(' ');
    if (parts.length === 2) {
        // Bearer 字段
        const scheme = parts[0];
        // token 字段
        const token = parts[1];
        if (/^Bearer$/i.test(scheme)) {
            // @ts-ignore
            const obj = this.verifyToken(token, type);
            if (!lodash_1.get(obj, 'type') || lodash_1.get(obj, 'type') !== type) {
              throw new Error('请使用正确类型的令牌');
            }
            if (!lodash_1.get(obj, 'scope') || lodash_1.get(obj, 'scope') !== 'lin') {
              throw new Error('请使用正确作用域的令牌');
            }
            return obj;
        }
    }
    else {
      throw new Error('请求头解析失败');
    }
  }

  base64url(string, encoding) {
    return Buffer
      .from(string, encoding)
      .toString('base64')
      .replace(/=/g, '')
      .replace(/\+/g, '-')
      .replace(/\//g, '_');
  }
}
export { jwt as JwtService};
