// Estimate acceptance rate of the demo's Gaussian sampler against our rejection bounds.

function boxMullerSample(sigma) {
  const u1 = Math.max(Math.random(), 1e-12);
  const u2 = Math.random();
  const z = Math.sqrt(-2 * Math.log(u1)) * Math.cos(2 * Math.PI * u2);
  return Math.max(-8, Math.min(8, Math.round(z * sigma)));
}

function samplePoly(n, sigma = 1.2) {
  const out = new Int16Array(n);
  for (let i = 0; i < n; i++) out[i] = boxMullerSample(sigma);
  return out;
}

function normSq(p) {
  let s = 0;
  for (let i = 0; i < p.length; i++) s += p[i] * p[i];
  return s;
}

function rate(n, bound, trials = 5000) {
  let accepts = 0;
  let attemptsHisto = new Array(8).fill(0);
  let totalAttempts = 0;
  for (let t = 0; t < trials; t++) {
    let attempt = 1;
    while (attempt <= 32) {
      const s = samplePoly(n);
      totalAttempts++;
      if (normSq(s) <= bound) {
        attemptsHisto[Math.min(attempt - 1, 7)]++;
        accepts++;
        break;
      }
      attempt++;
    }
  }
  return { accepts, trials, perAttempt: accepts / totalAttempts, attemptsHisto, avgAttempts: totalAttempts / trials };
}

for (const b of [780, 800, 820, 840, 860]) {
  const r = rate(512, b, 2000);
  console.log(`n=512 bound=${b}: accept ${(r.perAttempt * 100).toFixed(1)}%, avg attempts ${r.avgAttempts.toFixed(2)}`);
}
console.log();
for (const b of [1540, 1580, 1620, 1660, 1700]) {
  const r = rate(1024, b, 2000);
  console.log(`n=1024 bound=${b}: accept ${(r.perAttempt * 100).toFixed(1)}%, avg attempts ${r.avgAttempts.toFixed(2)}`);
}
