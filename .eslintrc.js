module.exports = {
  root: true,
  extends: ['@daotl/eslint-config/typescript'],
  parserOptions: {
    project: 'tsconfig.json',
  },
  rules: {
    '@typescript-eslint/restrict-plus-operands': 'off',
  },
}
