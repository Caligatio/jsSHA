import typescript from "@rollup/plugin-typescript";
import { terser } from "rollup-plugin-terser";

export default [
  {
    input: "src/sha.ts",
    output: {
      name: "jsSHA",
      format: "umd",
      sourcemap: true,
      dir: "dist",
    },
    plugins: [
      typescript({ lib: ["es6"], target: "es3" }),
      terser({ sourcemap: true, mangle: true, mangle: { properties: { reserved: ["jsSHA"] } } }),
    ],
  },
];
