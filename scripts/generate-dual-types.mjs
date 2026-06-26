import fs from "fs";

const variants = ["sha", "sha1", "sha256", "sha512", "sha3"];

for (const variant of variants) {
  const srcPath = `dist/${variant}.d.ts`;
  const esmContent = fs.readFileSync(srcPath, { encoding: "utf8" });

  if (!esmContent.includes("export { jsSHA as default };")) {
    throw new Error(
      `${srcPath} did not contain the expected "export { jsSHA as default };" line - ` +
        "the dts bundling output may have changed and this script needs updating."
    );
  }

  // dist/<variant>.mjs is genuine ESM and really does have a default export,
  // so the existing bundled declaration is already correct for it.
  fs.writeFileSync(`dist/${variant}.d.mts`, esmContent);

  // dist/<variant>.js is UMD/CJS and does `module.exports = jsSHA` (not
  // `module.exports.default = jsSHA`), so the CJS-facing declaration needs
  // `export =` instead of `export default` or TypeScript will think
  // consumers need a `.default` that doesn't exist at runtime.
  const cjsContent = esmContent.replace("export { jsSHA as default };", "export = jsSHA;");
  fs.writeFileSync(`dist/${variant}.d.cts`, cjsContent);

  // The bare top-level "types" field (used by tooling that ignores the
  // "exports" map entirely) is paired with "main", which is the CJS file -
  // so it needs the same `export =` treatment.
  fs.writeFileSync(srcPath, cjsContent);
}
