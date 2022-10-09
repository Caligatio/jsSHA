module.exports = {
  root: true,
  parser: "@typescript-eslint/parser",
  parserOptions: {
    project: "./tsconfig.json",
  },
  ignorePatterns: ["*.txt", "/dist", "/test/dist", ".eslintrc.js"],
  plugins: ["@typescript-eslint"],
  overrides: [
    {
      files: ["*.js", "*.mjs"],
      rules: {
        "@typescript-eslint/explicit-function-return-type": "off",
      },
    },
    {
      files: ["test/**"],
      rules: {
        "@typescript-eslint/no-unsafe-call": "off",
        "@typescript-eslint/no-unsafe-return": "off",
      },
    },
  ],
  extends: [
    "eslint:recommended",
    "plugin:@typescript-eslint/eslint-recommended",
    "plugin:@typescript-eslint/recommended",
    "plugin:@typescript-eslint/recommended-requiring-type-checking",
  ],
  rules: {
    "@typescript-eslint/ban-ts-comment": "off",
    "@typescript-eslint/no-unsafe-argument": "off",
    "@typescript-eslint/no-unsafe-assignment": "off",
    "@typescript-eslint/no-unsafe-member-access": "off",
    "@typescript-eslint/camelcase": "off",
    "@typescript-eslint/class-name-casing": "off",
    "@typescript-eslint/no-unused-vars": ["error", { argsIgnorePattern: "^_" }],
  },
};
