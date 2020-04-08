import fs from "fs";
import typescript from "@rollup/plugin-typescript";
import { terser } from "rollup-plugin-terser";

const licenseHeaderES3 = fs.readFileSync("src/license_header.es3.txt", { encoding: "utf8" }),
  licenseHeaderES6 = fs.readFileSync("src/license_header.es6.txt", { encoding: "utf8" });

export default [
  {
    input: "src/sha.ts",
    output: {
      name: "jsSHA",
      banner: licenseHeaderES3,
      format: "umd",
      sourcemap: true,
      dir: "./",
      entryFileNames: "dist/[name].js",
    },
    plugins: [
      typescript({ lib: ["es6"], declaration: true, declarationDir: "dist/types", target: "es3" }),
      terser({
        sourcemap: true,
        compress: { inline: false },
        output: { comments: /BSD/ },
        mangle: { properties: { keep_quoted: true, reserved: ["jsSHA", "getHash", "setHMACKey", "getHMAC"] } },
      }),
    ],
  },
  {
    input: "src/sha1.ts",
    output: {
      name: "jsSHA",
      banner: licenseHeaderES3,
      format: "umd",
      file: "dist/sha1.js",
    },
    plugins: [
      typescript({ lib: ["es6"], target: "es3" }),
      terser({
        compress: { inline: false },
        output: { comments: /BSD/ },
        mangle: { properties: { keep_quoted: true, reserved: ["jsSHA", "getHash", "setHMACKey", "getHMAC"] } },
      }),
    ],
  },
  {
    input: "src/sha256.ts",
    output: {
      name: "jsSHA",
      banner: licenseHeaderES3,
      format: "umd",
      file: "dist/sha256.js",
    },
    plugins: [
      typescript({ lib: ["es6"], target: "es3" }),
      terser({
        compress: { inline: false },
        output: { comments: /BSD/ },
        mangle: { properties: { keep_quoted: true, reserved: ["jsSHA", "getHash", "setHMACKey", "getHMAC"] } },
      }),
    ],
  },
  {
    input: "src/sha512.ts",
    output: {
      name: "jsSHA",
      banner: licenseHeaderES3,
      format: "umd",
      file: "dist/sha512.js",
    },
    plugins: [
      typescript({ lib: ["es6"], target: "es3" }),
      terser({
        compress: { inline: false },
        output: { comments: /BSD/ },
        mangle: { properties: { keep_quoted: true, reserved: ["jsSHA", "getHash", "setHMACKey", "getHMAC"] } },
      }),
    ],
  },
  {
    input: "src/sha3.ts",
    output: {
      name: "jsSHA",
      banner: licenseHeaderES3,
      format: "umd",
      file: "dist/sha3.js",
    },
    plugins: [
      typescript({ lib: ["es6"], target: "es3" }),
      terser({
        compress: { inline: false },
        output: { comments: /BSD/ },
        mangle: { properties: { keep_quoted: true, reserved: ["jsSHA", "getHash", "setHMACKey", "getHMAC"] } },
      }),
    ],
  },
  {
    input: "src/sha.ts",
    output: {
      name: "jsSHA",
      banner: licenseHeaderES6,
      format: "es",
      sourcemap: true,
      file: "dist/sha.mjs",
    },
    plugins: [
      typescript({ lib: ["es6"], target: "es6" }),
      terser({
        sourcemap: true,
        compress: { inline: false },
        output: { comments: /BSD/ },
        mangle: { properties: { keep_quoted: true, reserved: ["jsSHA", "getHash", "setHMACKey", "getHMAC"] } },
      }),
    ],
  },
];
