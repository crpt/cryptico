import { cryptico, md5, RSAKey } from '../../dist/node/'

const key: RSAKey = cryptico.generateRSAKey('Made with love by DAOT Labs', 512)
console.log(md5(JSON.stringify(key)))
