// INTENTIONAL INSECURE FIXTURE — demo/test only. Not production code.
// Intentionally vulnerable JS sample
const { exec } = require('child_process');

function run(userDir) {
  eval(userDir); // bad
  exec(`ls ${userDir}`); // injection
  document.innerHTML = userDir; // xss-ish
}

module.exports = { run };
