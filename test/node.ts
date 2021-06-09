import { cryptico, MD5, RSAKey } from '../dist/cryptico.es5'
const key: RSAKey = cryptico.generateRSAKey('Made with love by DAOT Labs', 512)
console.log(MD5(JSON.stringify(key)))
