/* globals module */
module.exports = function (config) {
  const shaVariant = config.fileVariant || "sha";

  config.set({
    frameworks: ["mocha", "chai"],
    files: ["dist/" + shaVariant + ".js", "test/hash_data.js", "test/dist/test_umd.js"],
    reporters: ["progress"],
    port: 9876, // karma web server port
    colors: true,
    logLevel: config.LOG_INFO,
    browsers: ["ChromeHeadless", "FirefoxHeadless"],
    autoWatch: false,
    singleRun: true,
    concurrency: Infinity,
    client: {
      mocha: {
        timeout: 10000, // 10 seconds - upped from 2 seconds
      },
    },
  });
};
