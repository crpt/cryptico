import { RollupOptions } from 'rollup'
import typescript from 'rollup-plugin-typescript2'
import dts from 'rollup-plugin-dts'

const pkg = require('./package.json')
const name = 'cryptico'

export default [
  {
    input: 'src/index.ts',
    output: [
      {
        file: pkg.main,
        format: 'umd',
        name,
        sourcemap: true,
      },
      { file: pkg.module, format: 'es', sourcemap: true },
      {
        file: pkg.browser,
        format: 'iife',
        name,
        sourcemap: true,
      },
    ],
    plugins: [
      typescript({
        tsconfig: 'tsconfig.build.json',
        useTsconfigDeclarationDir: true,
      }),
    ],
  },
  {
    input: 'types/index.d.ts',
    output: [{ file: 'dist/types/cryptico.d.ts' }],
    plugins: [dts()],
  },
] as RollupOptions
