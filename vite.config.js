import * as path from 'path'

const config = {
  build: {
    lib: {
      name: 'cryptico',
      entry: path.resolve(__dirname, 'src/api.js'),
    },
    sourcemap: true,
  },
}

export default config
