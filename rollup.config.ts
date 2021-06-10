import { RollupOptions } from 'rollup'
import injectProcessEnv from 'rollup-plugin-inject-process-env'
import typescript from 'rollup-plugin-typescript2'
import { terser } from 'rollup-plugin-terser'
import dts from 'rollup-plugin-dts'

const env = process.env.NODEJS ? 'node' : 'native'
const pkg = require('./package.json')
const name = 'cryptico'

export default [
  {
    input: 'src/index.ts',
    output: [
      {
        file: `dist/${env}/${pkg.main}`,
        format: env === 'node' ? 'cjs' : 'umd',
        name,
        sourcemap: true,
      },
      { file: `dist/${env}/${pkg.module}`, format: 'es', sourcemap: true },
    ].concat(
      env === 'native'
        ? {
            file: `dist/${pkg.browser}`,
            format: 'iife',
            name,
            sourcemap: true,
          }
        : [],
    ),
    plugins: [
      injectProcessEnv({
        NODEJS: process.env.NODEJS,
      }),
      typescript({
        tsconfig: 'tsconfig.build.json',
        useTsconfigDeclarationDir: true,
        tsconfigOverride: {
          compilerOptions: {
            declarationDir: `dist/types`,
          },
        },
      }),
      terser(),
    ],
  },
  {
    input: 'dist/types/index.d.ts',
    output: [{ file: 'dist/index.d.ts' }],
    plugins: [dts()],
  },
] as RollupOptions
