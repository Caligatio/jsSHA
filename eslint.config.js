const js = require("@eslint/js");
const tseslint = require("typescript-eslint");

module.exports = tseslint.config(
  {
    ignores: ["karma.conf.js", "rollup.config.mjs", "coverage/", "dist/**", "test/dist/**", "eslint.config.js"],
  },

  js.configs.recommended,
  ...tseslint.configs.recommendedTypeChecked,

  {
    languageOptions: {
      parserOptions: {
        projectService: {
          allowDefaultProject: ["test/*.js"],
        },
        tsconfigRootDir: __dirname,
      },
    },
    rules: {
      "@typescript-eslint/ban-ts-comment": "off",
      "@typescript-eslint/no-unsafe-argument": "off",
      "@typescript-eslint/no-unsafe-assignment": "off",
      "@typescript-eslint/no-unsafe-member-access": "off",
      "@typescript-eslint/camelcase": "off",
      "@typescript-eslint/class-name-casing": "off",
      "@typescript-eslint/no-unused-vars": ["error", { argsIgnorePattern: "^_" }],
      "preserve-caught-error": "off",
    },
  },

  {
    files: ["**/*.js", "**/*.mjs"],
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
);
