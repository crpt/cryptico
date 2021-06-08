import * as path from 'path'
import { UserConfig } from 'vite'

const config: UserConfig = {
  build: {
    lib: {
      name: 'cryptico',
      entry: path.resolve(__dirname, 'src/api.ts'),
    },
    sourcemap: true,
  },
}

export default config
