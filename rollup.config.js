let fs = require("fs");
import typescript from "@rollup/plugin-typescript";
import { terser } from "rollup-plugin-terser";

let licenseHeader = fs.readFileSync("src/license_header.txt", { encoding: "utf8" });

export default [
  {
    input: "src/sha.ts",
    output: {
      name: "jsSHA",
      banner: licenseHeader,
      format: "umd",
      sourcemap: true,
      dir: "dist",
      entryFileNames: "[name].umd.js"
    },
    plugins: [
      typescript({ lib: ["es6"], target: "es3" }),
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
      banner: licenseHeader,
      format: "umd",
      sourcemap: true,
      dir: "dist",
      entryFileNames: "[name].umd.js"
    },
    plugins: [
      typescript({ lib: ["es6"], target: "es3" }),
      terser({
        sourcemap: true,
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
      banner: licenseHeader,
      format: "umd",
      sourcemap: true,
      dir: "dist",
      entryFileNames: "[name].umd.js"
    },
    plugins: [
      typescript({ lib: ["es6"], target: "es3" }),
      terser({
        sourcemap: true,
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
      banner: licenseHeader,
      format: "umd",
      sourcemap: true,
      dir: "dist",
      entryFileNames: "[name].umd.js"
    },
    plugins: [
      typescript({ lib: ["es6"], target: "es3" }),
      terser({
        sourcemap: true,
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
      banner: licenseHeader,
      format: "umd",
      sourcemap: true,
      dir: "dist",
      entryFileNames: "[name].umd.js"
    },
    plugins: [
      typescript({ lib: ["es6"], target: "es3" }),
      terser({
        sourcemap: true,
        compress: { inline: false },
        output: { comments: /BSD/ },
        mangle: { properties: { keep_quoted: true, reserved: ["jsSHA", "getHash", "setHMACKey", "getHMAC"] } },
      }),
    ],
  },
];
