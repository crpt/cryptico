import aes, { AESKey } from './aes'
import { int2char } from './jsbn'
import { math, SecureRandom } from './random'
import { MD5, sha256 } from './hash'
import { RSAKey } from './rsa'
import { ByteArray } from './type'

const base64Chars =
  'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
const magic = '::52cee64bb3a38f6403386519a39ac91c::'

aes.Init()

type DecryptStatusSuccessForSignature<Signature> = {
  status: 'success'
  plaintext: string
  signature: Signature
  publicKeyString: Signature extends 'unsigned' ? never : string
}
type DecryptStatusSuccess =
  | DecryptStatusSuccessForSignature<'unsigned'>
  | DecryptStatusSuccessForSignature<'verified' | 'forged'>
type DecryptStatusFailure = { status: 'Invalid public key' | 'failure' }

export class cryptico {
  static b256to64(t: string): string {
    let a = 0, // Should be reassigned before read
      c,
      n
    let r = '',
      // l = 0,
      s = 0
    const tl = t.length
    for (n = 0; n < tl; n++) {
      c = t.charCodeAt(n)
      if (s === 0) {
        r += base64Chars.charAt((c >> 2) & 63)
        a = (c & 3) << 4
      } else if (s === 1) {
        r += base64Chars.charAt(a | ((c >> 4) & 15))
        a = (c & 15) << 2
      } else if (s === 2) {
        r += base64Chars.charAt(a | ((c >> 6) & 3))
        // l += 1
        r += base64Chars.charAt(c & 63)
      }
      // l += 1
      s += 1
      if (s === 3) s = 0
    }
    if (s > 0) {
      r += base64Chars.charAt(a)
      // l += 1
      r += '='
      // l += 1
    }
    if (s === 1) {
      r += '='
    }
    return r
  }

  static b64to256(t: string): string {
    let c, n
    let r = '',
      s = 0,
      a = 0
    const tl = t.length
    for (n = 0; n < tl; n++) {
      c = base64Chars.indexOf(t.charAt(n))
      if (c >= 0) {
        if (s) r += String.fromCharCode(a | ((c >> (6 - s)) & 255))
        s = (s + 2) & 7
        a = (c << s) & 255
      }
    }
    return r
  }

  static b16to64(h: string): string {
    let i
    let c
    let ret = ''
    if (h.length % 2 === 1) {
      h = '0' + h
    }
    for (i = 0; i + 3 <= h.length; i += 3) {
      c = parseInt(h.substring(i, i + 3), 16)
      ret += base64Chars.charAt(c >> 6) + base64Chars.charAt(c & 63)
    }
    if (i + 1 === h.length) {
      c = parseInt(h.substring(i, i + 1), 16)
      ret += base64Chars.charAt(c << 2)
    } else if (i + 2 === h.length) {
      c = parseInt(h.substring(i, i + 2), 16)
      ret += base64Chars.charAt(c >> 2) + base64Chars.charAt((c & 3) << 4)
    }
    while ((ret.length & 3) > 0) ret += '='
    return ret
  }

  static b64to16(s: string): string {
    let ret = ''
    let i
    let k = 0
    let slop = 0 // Should be reassigned before read
    for (i = 0; i < s.length; ++i) {
      if (s.charAt(i) === '=') break
      const v = base64Chars.indexOf(s.charAt(i))
      if (v < 0) continue
      if (k === 0) {
        ret += int2char(v >> 2)
        slop = v & 3
        k = 1
      } else if (k === 1) {
        ret += int2char((slop << 2) | (v >> 4))
        slop = v & 0xf
        k = 2
      } else if (k === 2) {
        ret += int2char(slop)
        ret += int2char(v >> 2)
        slop = v & 3
        k = 3
      } else {
        ret += int2char((slop << 2) | (v >> 4))
        ret += int2char(v & 0xf)
        k = 0
      }
    }
    if (k === 1) ret += int2char(slop << 2)
    return ret
  }

  // Converts a string to a byte array.
  static string2bytes(str: string): ByteArray {
    const bytes = []
    for (let i = 0; i < str.length; i++) {
      bytes.push(str.charCodeAt(i))
    }
    return bytes
  }

  // Converts a byte array to a string.
  static bytes2string(bytes: ByteArray): string {
    let str = ''
    for (let i = 0; i < bytes.length; i++) {
      str += String.fromCharCode(bytes[i])
    }
    return str
  }

  // Converts a UTF-8 string to ASCII string.
  static utf82string(str: string): string {
    return unescape(encodeURIComponent(str))
  }

  // Converts ascii string to a UTF-8 string.
  static string2utf8(uriencoded: string): string {
    return decodeURIComponent(escape(uriencoded))
  }

  // Converts a UTF-8 string to a byte array.
  static utf82bytes(str: string): ByteArray {
    const uriencoded = unescape(encodeURIComponent(str))
    return this.string2bytes(uriencoded)
  }

  // Converts a byte array to a UTF-8 string.
  static bytes2utf8(bytes: ByteArray): string {
    const uriencoded = this.bytes2string(bytes)
    return decodeURIComponent(escape(uriencoded))
  }

  // Returns a XOR b, where a and b are 16-byte byte arrays.
  static blockXOR(a: ByteArray, b: ByteArray): ByteArray {
    const xor = new Array(16) as ByteArray
    for (let i = 0; i < 16; i++) {
      xor[i] = a[i] ^ b[i]
    }
    return xor
  }

  // Returns a 16-byte initialization vector.
  static blockIV(): ByteArray {
    const r = new SecureRandom()
    const IV = new Array(16) as ByteArray
    r.nextBytes(IV)
    return IV
  }

  // Returns a copy of bytes with zeros appended to the end
  // so that the (length of bytes) % 16 === 0.
  static pad16(bytes: ByteArray): ByteArray {
    const newBytes = bytes.slice(0)
    const padding = (16 - (bytes.length % 16)) % 16
    for (let i = bytes.length; i < bytes.length + padding; i++) {
      newBytes.push(0)
    }
    return newBytes
  }

  // Removes trailing zeros from a byte array.
  static depad(bytes: ByteArray): ByteArray {
    let newBytes = bytes.slice(0)
    while (newBytes[newBytes.length - 1] === 0) {
      newBytes = newBytes.slice(0, newBytes.length - 1)
    }
    return newBytes
  }

  // AES CBC Encryption.
  static encryptAESCBC(plaintext: string, key: AESKey): string {
    const exkey = key.slice(0)
    aes.ExpandKey(exkey)
    let blocks = this.utf82bytes(plaintext)
    blocks = this.pad16(blocks)
    let encryptedBlocks = this.blockIV()
    for (let i = 0; i < blocks.length / 16; i++) {
      let tempBlock = blocks.slice(i * 16, i * 16 + 16)
      const prevBlock = encryptedBlocks.slice(i * 16, i * 16 + 16)
      tempBlock = this.blockXOR(prevBlock, tempBlock)
      aes.Encrypt(tempBlock, exkey)
      encryptedBlocks = encryptedBlocks.concat(tempBlock)
    }
    const ciphertext = this.bytes2string(encryptedBlocks)
    return this.b256to64(ciphertext)
  }

  // AES CBC Decryption.
  static decryptAESCBC(encryptedText: string, key: AESKey): string {
    const exkey = key.slice(0)
    aes.ExpandKey(exkey)
    const asciiText = this.b64to256(encryptedText)
    const encryptedBlocks = this.string2bytes(asciiText)
    let decryptedBlocks: ByteArray = []
    for (let i = 1; i < encryptedBlocks.length / 16; i++) {
      let tempBlock = encryptedBlocks.slice(i * 16, i * 16 + 16)
      const prevBlock = encryptedBlocks.slice((i - 1) * 16, (i - 1) * 16 + 16)
      aes.Decrypt(tempBlock, exkey)
      tempBlock = this.blockXOR(prevBlock, tempBlock)
      decryptedBlocks = decryptedBlocks.concat(tempBlock)
    }
    decryptedBlocks = this.depad(decryptedBlocks)
    return this.bytes2utf8(decryptedBlocks)
  }

  // Wraps a str to 60 characters.
  static wrap60(str: string): string {
    let outstr = ''
    for (let i = 0; i < str.length; i++) {
      if (i % 60 === 0 && i !== 0) outstr += '\n'
      outstr += str[i]
    }
    return outstr
  }

  // Generate a random key for the AES-encrypted message. ciphertext.split
  static generateAESKey(): AESKey {
    const key = new Array(32) as ByteArray
    const r = new SecureRandom()
    r.nextBytes(key)
    return key
  }

  // Generates an RSA key from a passphrase.
  static generateRSAKey(passphrase: string, bitlength: number): RSAKey {
    math.seedrandom(sha256.hex(passphrase))
    const rsa = new RSAKey()
    rsa.generate(bitlength, '03')
    return rsa
  }

  // Returns the ascii-armored version of the public key.
  static publicKeyString(rsakey: RSAKey): string {
    return this.b16to64(rsakey.n.toString(16))
  }

  // Returns an MD5 sum of a publicKeyString for easier identification.
  static publicKeyID(publicKeyString: string): string {
    return MD5(publicKeyString)
  }

  static publicKeyFromString(str: string): RSAKey {
    const N = this.b64to16(str.split('|')[0])
    const E = '03'
    const rsa = new RSAKey()
    rsa.setPublic(N, E)
    return rsa
  }

  static encrypt(
    plaintext: string,
    publickeystring: string,
    signingkey: RSAKey,
  ): { status: string } | { status: 'success'; cipher: string } {
    {
      let cipherblock = ''
      const aeskey = this.generateAESKey()
      try {
        const publickey = this.publicKeyFromString(publickeystring)
        cipherblock +=
          this.b16to64(publickey.encrypt(this.bytes2string(aeskey))) + '?'
      } catch (err) {
        return { status: 'Invalid public key' }
      }
      if (signingkey) {
        const signString = this.sign(plaintext, signingkey)
        plaintext += magic
        plaintext += this.publicKeyString(signingkey)
        plaintext += magic
        plaintext += signString
      }
      cipherblock += this.encryptAESCBC(plaintext, aeskey)
      return { status: 'success', cipher: cipherblock }
    }
  }

  static decrypt(
    ciphertext: string,
    key: RSAKey,
  ): DecryptStatusSuccess | DecryptStatusFailure {
    const cipherblock = ciphertext.split('?')
    const aeskey = key.decrypt(this.b64to16(cipherblock[0]))
    if (aeskey == null) {
      return { status: 'failure' }
    }
    const aeskeyBytes = this.string2bytes(aeskey)
    const plaintext = this.decryptAESCBC(cipherblock[1], aeskeyBytes).split(
      magic,
    )
    if (plaintext.length > 1) {
      return this._confirm(plaintext)
    } else
      return {
        status: 'success',
        plaintext: plaintext[0],
        signature: 'unsigned',
      } as DecryptStatusSuccessForSignature<'unsigned'>
  }

  static sign(plaintext: string, signingkey: RSAKey): string {
    return this.b16to64(signingkey.signString(plaintext, 'sha256'))
  }

  static verify(plaintext: string[]): boolean {
    const result = this._confirm(plaintext)
    return result.status === 'success' && result.signature === 'verified'
  }

  private static _confirm(
    plaintext: string[],
  ): DecryptStatusSuccess | DecryptStatusFailure {
    if (plaintext.length === 3) {
      const publickey = this.publicKeyFromString(plaintext[1])
      const signature = this.b64to16(plaintext[2])
      if (publickey.verifyString(plaintext[0], signature)) {
        return {
          status: 'success',
          plaintext: plaintext[0],
          signature: 'verified',
          publicKeyString: this.publicKeyString(publickey),
        }
      } else {
        return {
          status: 'success',
          plaintext: plaintext[0],
          signature: 'forged',
          publicKeyString: this.publicKeyString(publickey),
        }
      }
    } else {
      return {
        status: 'failure',
      }
    }
  }
}
