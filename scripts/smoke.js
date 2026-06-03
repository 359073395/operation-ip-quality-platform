const { analyzeIp } = require("../src/services/ipAnalyzer");

(async () => {
  const result = await analyzeIp({
    ip: "8.8.8.8",
    runReachability: false,
  });

  if (!result.score || typeof result.score.score !== "number") {
    throw new Error("Smoke check failed: missing score.");
  }

  console.log(`Smoke check OK: ${result.input.ip} => ${result.score.score}/${result.score.grade}`);
})();
