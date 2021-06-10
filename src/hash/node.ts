import crypto from 'crypto'

export function sha256(msg: string): string {
  return crypto.createHash('sha256').update(msg, 'utf8').digest('hex')
}

export function sha1(msg: string): string {
  return crypto.createHash('sha1').update(msg, 'utf8').digest('hex')
}

export function md5(msg: string): string {
  return crypto.createHash('md5').update(msg, 'utf8').digest('hex')
}
