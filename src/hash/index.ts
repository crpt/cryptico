import * as native from './native'
import * as node from './node'

export type HashFunc = (s: string) => string

export const sha256 = (
  process.env.NODEJS ? node.sha256 : native.sha256
) as HashFunc

export const sha1 = (process.env.NODEJS ? node.sha1 : native.sha1) as HashFunc

export const md5 = (process.env.NODEJS ? node.md5 : native.md5) as HashFunc
