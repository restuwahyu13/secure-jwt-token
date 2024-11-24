# Secure Jwt Access Token

Berikut adalah bagaimana cara membuat, **Secure** dan **Strong** `JWT Access Token` dengan menggunakan `Asymmetric Cryptography` dengan `Jose Library`, cara ini saya buat kurang lebih 1 tahun yang lalu ketika saya masih berkerja di `pazemo`, yang dimana tujuan dari tutorial yang saya buat ini, adalah untuk meminimalisir terjadi nya authentication bypass seperti video attacker berikut ini [JWT Authentication Bypass](https://www.youtube.com/watch?v=ov9yT4WAuzI), dikarenakan hanya menerapkan `JWT Access Token` standar implementasi.

## Benefit

- [x] Secure & Strong JWT Token
- [x] Dynamic Secret Key JWT Token
- [x] Dynamic Asymmetric Password
- [x] Strict identity access management
- [x] Server Side Validation

## NodeJS Version

- ### JOSE

```ts
import crypto from 'node:crypto'
import * as jose from 'jose'
import { JwtPayload } from 'jsonwebtoken'

import { ISignatureMetadata } from '~/libs/lib.jwt'
import { Redis } from '~/libs/lib.redis'
import { apiResponse } from '~/helpers/helper.apiResponse'

export class Jose {
  private redis: InstanceType<typeof Redis> = new Redis()

  static JweEncrypt(privateKey: jose.KeyLike | crypto.KeyObject, data: string): Promise<jose.FlattenedJWE> {
    try {
      const text: Uint8Array = new TextEncoder().encode(data)
      const jwe: jose.FlattenedEncrypt = new jose.FlattenedEncrypt(text).setProtectedHeader({
        alg: 'RSA-OAEP',
        enc: 'A256CBC-HS512',
        typ: 'JWT',
        cty: 'JWT',
      })

      return jwe.encrypt(privateKey)
    } catch (e: any) {
      throw apiResponse(e)
    }
  }

  static async JweDecerypt(privateKey: jose.KeyLike | crypto.KeyObject, jweEncryption: jose.FlattenedJWE): Promise<string> {
    try {
      const jwe: jose.FlattenedDecryptResult = await jose.flattenedDecrypt(jweEncryption, privateKey)
      const text: string = new TextDecoder().decode(jwe.plaintext)

      return text
    } catch (e: any) {
      throw apiResponse(e)
    }
  }

  static importJsonWebKey(jwkExport: jose.JWK): Promise<jose.KeyLike | Uint8Array> {
    try {
      return jose.importJWK(jwkExport)
    } catch (e: any) {
      throw apiResponse(e)
    }
  }

  static exportJsonWebKey(privateKey: jose.KeyLike | crypto.KeyObject): Promise<jose.JWK> {
    try {
      return jose.exportJWK(privateKey)
    } catch (e: any) {
      throw apiResponse(e)
    }
  }

  static JwtSign(privateKey: jose.KeyLike | crypto.KeyObject, headerKeyId: string, data: Record<string, any>, options: JwtPayload): Promise<string> {
    try {
      return new jose.SignJWT(data)
        .setProtectedHeader({ alg: 'RS512', typ: 'JWT', cty: 'JWT', kid: headerKeyId, b64: true })
        .setAudience(options.aud)
        .setIssuer(options.iss)
        .setSubject(options.sub)
        .setIssuedAt(options.iat)
        .setExpirationTime(options.exp)
        .setJti(options.jti)
        .sign(privateKey)
    } catch (e: any) {
      throw apiResponse(e)
    }
  }

  async JwtVerify(prefix: string, token: string): Promise<jose.JWTVerifyResult<jose.JWTPayload>> {
    try {
      const signatureKey: string = `${prefix}:credential`
      const signatureMetadataField: string = 'signature_metadata'

      const signature: ISignatureMetadata = await this.redis.hget(signatureKey, signatureMetadataField)
      if (!signature) {
        throw new Error('Invalid signature 1')
      }

      const rsaPrivateKey: crypto.KeyObject = crypto.createPrivateKey({ key: signature.privKeyRaw, passphrase: signature.cipherKey })
      if (!rsaPrivateKey) {
        throw new Error('Invalid signature 2')
      }

      const jwsVerify: jose.CompactVerifyResult = await jose.compactVerify(token, rsaPrivateKey)
      if (jwsVerify.protectedHeader.kid !== signature.jweKey.ciphertext) {
        throw new Error('Invalid signature 3')
      }

      const aud: string = signature.sigKey.substring(10, 25)
      const iss: string = signature.sigKey.substring(20, 35)
      const sub: string = signature.sigKey.substring(40, 55)

      return jose.jwtVerify(token, rsaPrivateKey, {
        audience: aud,
        issuer: iss,
        subject: sub,
        algorithms: [jwsVerify.protectedHeader.alg],
        typ: jwsVerify.protectedHeader.typ,
      })
    } catch (e: any) {
      throw apiResponse(e)
    }
  }
}
```

- ### JWT

```ts
import crypto from 'node:crypto'
import * as jose from 'jose'
import moment from 'moment-timezone'

import { Redis } from '~/libs/lib.redis'
import { Encryption } from '~/helpers/helper.encryption'
import { Jose } from '~/libs/lib.jose'
import { Environment } from '~/configs/config.env'
import { apiResponse } from '~/helpers/helper.apiResponse'

export interface ISecretMetadata {
  privKeyRaw: string
  pubKeyRaw: string
  cipherKey: string
}

export interface ISignatureMetadata {
  privKey?: crypto.KeyObject
  privKeyRaw: string
  sigKey: string
  cipherKey: string
  jweKey: jose.FlattenedJWE
}

export class JsonWebToken {
  private redis: InstanceType<typeof Redis> = new Redis()
  private keyLength: number = 4096
  private jwtExpired: number = Environment.JWT_EXPIRED
  private certMetadata: ISecretMetadata = {
    privKeyRaw: '',
    pubKeyRaw: '',
    cipherKey: '',
  }
  private sigMetadata: ISignatureMetadata = {
    privKeyRaw: '',
    privKey: {} as any,
    sigKey: '',
    cipherKey: '',
    jweKey: {} as any,
  }

  private createSecret(prefix: string, body: string): ISecretMetadata {
    try {
      const randomString: string = crypto.randomBytes(16).toString('hex')

      const cipherTextRandom: string = `${prefix}:${body}:${randomString}:${this.jwtExpired}`
      const cipherTextData: string = Buffer.from(cipherTextRandom).toString('hex')

      const cipherSecretKey: string = crypto.createHash('SHA512').update(cipherTextData).digest().toString('hex')
      const cipherText: string = crypto.createHash('SHA512').update(randomString).digest().toString('hex')
      const cipherKey: string = Encryption.AES256Encrypt(cipherSecretKey, cipherText).toString('hex')

      const genCert: crypto.KeyPairSyncResult<string, string> = crypto.generateKeyPairSync('rsa', {
        modulusLength: this.keyLength,
        publicKeyEncoding: {
          type: 'pkcs1',
          format: 'pem',
        },
        privateKeyEncoding: {
          type: 'pkcs8',
          format: 'pem',
          cipher: 'aes-256-cbc',
          passphrase: cipherKey,
        },
      })

      this.certMetadata = {
        privKeyRaw: genCert.privateKey,
        pubKeyRaw: genCert.publicKey,
        cipherKey: cipherKey,
      }

      return this.certMetadata
    } catch (e: any) {
      throw apiResponse(e)
    }
  }

  private async createSignature(prefix: string, body: any): Promise<ISignatureMetadata> {
    try {
      const signatureKey: string = `${prefix}:credential`
      const signatureField: string = 'signature_metadata'

      body = Buffer.from(JSON.stringify(body))
      const secretKey: ISecretMetadata = this.createSecret(prefix, body)

      const rsaPrivateKey: crypto.KeyObject = crypto.createPrivateKey({
        key: Buffer.from(secretKey.privKeyRaw),
        type: 'pkcs8',
        format: 'pem',
        passphrase: secretKey.cipherKey,
      })

      const rsaPublicKey: crypto.KeyObject = crypto.createPublicKey({
        key: Buffer.from(secretKey.pubKeyRaw),
        type: 'pkcs1',
        format: 'pem',
      })

      const cipherHash512: Buffer = crypto.sign('RSA-SHA512', body, rsaPrivateKey)
      const signatureOutput: string = cipherHash512.toString('hex')

      const verifiedSignature = crypto.verify('RSA-SHA512', body, rsaPublicKey, cipherHash512)
      if (!verifiedSignature) throw new Error('Invalid signature')

      const jweKey: jose.FlattenedJWE = await Jose.JweEncrypt(rsaPrivateKey, signatureOutput)
      if (!jweKey) throw new Error('Invalid encrypt')

      this.sigMetadata = {
        privKeyRaw: secretKey.privKeyRaw,
        sigKey: signatureOutput,
        cipherKey: secretKey.cipherKey,
        jweKey: jweKey,
      }

      await this.redis.hsetEx(signatureKey, signatureField, this.jwtExpired, this.sigMetadata)
      this.sigMetadata.privKey = rsaPrivateKey

      return this.sigMetadata
    } catch (e: any) {
      throw apiResponse(e)
    }
  }

  async sign(prefix: string, body: any): Promise<string> {
    try {
      const tokenKey: string = `${prefix}:token`
      const tokenExist: number = await this.redis.exists(tokenKey)

      if (tokenExist < 1) {
        const signature: ISignatureMetadata = await this.createSignature(prefix, body)
        const timestamp: string = moment().format('YYYY/MM/DD HH:mm:ss')

        const aud: string = signature.sigKey.substring(10, 25)
        const iss: string = signature.sigKey.substring(20, 35)
        const sub: string = signature.sigKey.substring(40, 55)

        const secretKey: string = `${aud}:${iss}:${sub}:${this.jwtExpired}`
        const secretData: string = Buffer.from(secretKey).toString('hex')

        const jti: string = Encryption.AES256Encrypt(secretData, prefix).toString('hex')

        const iat: number = Math.floor(Date.now() / 1000) + 60 * 60
        const exp: number = iat + this.jwtExpired

        const tokenData: string = await Jose.JwtSign(
          signature.privKey,
          signature.jweKey.ciphertext,
          { timestamp: timestamp },
          {
            jti: jti,
            aud: aud,
            iss: iss,
            sub: sub,
            iat: iat,
            exp: exp,
          },
        )

        this.redis.setEx(tokenKey, this.jwtExpired, tokenData)

        return tokenData
      } else {
        return this.redis.get(tokenKey)
      }
    } catch (e: any) {
      throw apiResponse(e)
    }
  }

  verify(prefix: string, token: string): Promise<jose.JWTVerifyResult<jose.JWTPayload>> {
    try {
      return new Jose().JwtVerify(prefix, token)
    } catch (e: any) {
      throw apiResponse(e)
    }
  }
}
```
- ### Middleware Auth

```ts
import { NextFunction, Request, Response } from 'express'
import { OutgoingMessage } from 'node:http'
import { StatusCodes as status } from 'http-status-codes'
import jsonwebtoken, { JwtPayload } from 'jsonwebtoken'
import validator from 'validator'
import { JWTPayload, JWTVerifyResult } from 'jose'

import { apiResponse } from '~/helpers/helper.apiResponse'
import { Container, Injectable } from '~/helpers/helper.di'
import { Encryption } from '~/helpers/helper.encryption'
import { JsonWebToken } from '~/libs/lib.jwt'

@Injectable()
export class AuthMiddleware {
  async use(req: Request, res: Response, next: NextFunction): Promise<OutgoingMessage> {
    try {
      const jwt: InstanceType<typeof JsonWebToken> = new JsonWebToken()
      const headers: Record<string, any> = req.headers

      if (!headers.hasOwnProperty('authorization')) {
        throw apiResponse({ stat_code: status.UNAUTHORIZED, error: 'Authorization required' })
      } else if (!Array.isArray(headers.authorization.match('Bearer'))) {
        throw apiResponse({ stat_code: status.UNAUTHORIZED, error: 'Unauthorized invalid token' })
      }

      let authToken: string = headers.authorization.split('Bearer ')[1]
      if (!validator.isJWT(authToken)) {
        throw apiResponse({ stat_code: status.UNAUTHORIZED, error: 'Unauthorized invalid token' })
      }

      const jwtDecode: JwtPayload = jsonwebtoken.decode(authToken) as any
      if (!jwtDecode) {
        throw apiResponse({ stat_code: status.UNAUTHORIZED, error: 'Unauthorized invalid token' })
      }

      const secretKey: string = Buffer.from(`${jwtDecode.aud}:${jwtDecode.iss}:${jwtDecode.sub}:${process.env.JWT_EXPIRED}`).toString('hex')
      const secretData: Buffer = Buffer.from(jwtDecode.jti, 'hex')
      const jti: string = Encryption.AES256Decrypt(secretKey, secretData).toString()

      const verifyRes: JWTVerifyResult<JWTPayload> = await jwt.verify(jti, authToken)
      if (!verifyRes) {
        throw apiResponse({ stat_code: status.UNAUTHORIZED, error: 'Unauthorized invalid token' })
      }

      const userId: string = jti
      Container.register('User', { useValue: userId })

      next()
    } catch (e: any) {
      return apiResponse({ stat_code: status.UNAUTHORIZED, error: 'Unauthorized invalid token' }, res)
    }
  }
}
```
