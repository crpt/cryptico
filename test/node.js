const { cryptico, md5 } = require('../dist/node/cryptico')

const key = cryptico.generateRSAKey('Made with love by DAOT Labs', 512)
console.log(md5(JSON.stringify(key)))
