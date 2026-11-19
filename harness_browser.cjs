// P-001 browser proof: serve the bundled host page (real published
// @plasmicpkgs/plasmic-cms components) on http://127.0.0.1:8899, open it in
// headless Chromium, and check whether the stored CMS rich-text payloads
// EXECUTE in the page (window.__xss populated by the payloads themselves).
const http = require("http");
const fs = require("fs");
const path = require("path");
const { chromium } = require("playwright-core");

const DB_ID = process.env.CMS_DB_ID;
const TOKEN = process.env.CMS_PUBLIC_TOKEN;
if (!DB_ID || !TOKEN) { console.error("set CMS_DB_ID and CMS_PUBLIC_TOKEN"); process.exit(2); }

const MIME = { ".html": "text/html", ".js": "text/javascript" };
const server = http.createServer((req, res) => {
  const p = req.url.split("?")[0];
  const file = path.join(__dirname, "www", p === "/" ? "index.html" : p);
  fs.readFile(file, (err, data) => {
    if (err) { res.writeHead(404); res.end("nf"); return; }
    res.writeHead(200, { "Content-Type": MIME[path.extname(file)] || "application/octet-stream" });
    res.end(data);
  });
});

(async () => {
  await new Promise((r) => server.listen(8899, "127.0.0.1", r));
  const browser = await chromium.launch({ args: ["--no-sandbox"] });
  const page = await browser.newPage();
  const url = `http://127.0.0.1:8899/?db=${DB_ID}&token=${encodeURIComponent(TOKEN)}`;
  await page.goto(url, { waitUntil: "load" });
  // wait for CMS rows to render
  await page.waitForFunction(() => document.body.innerText.includes("hello"), null, { timeout: 20000 }).catch(() => {});
  await page.waitForTimeout(2500); // let img onerror / svg onload / iframe srcdoc fire
  const xss = await page.evaluate(() => window.__xss || []);
  const html = await page.evaluate(() => document.getElementById("root").innerHTML);
  console.log(`info: svg-onload fired: ${xss.includes("svg-onload")} (did not fire in this Chromium run; img/iframe vectors did)`);
  const checks = [
    ["attack row rendered", html.includes("hello")],
    ["control row rendered", html.includes("control")],
    ["img onerror EXECUTED in Chromium", xss.includes("img-onerror")],
    ["iframe srcdoc EXECUTED in Chromium", xss.includes("iframe-srcdoc")],
    ["AT LEAST ONE payload EXECUTED", xss.length > 0],
  ];
  let ok = true;
  for (const [name, pass] of checks) { console.log(`${pass ? "PASS" : "FAIL"}  ${name}`); ok = ok && pass; }
  console.log("window.__xss =", JSON.stringify(xss));
  await browser.close();
  server.close();
  process.exit(ok ? 0 : 1);
})().catch((e) => { console.error(e); process.exit(2); });
