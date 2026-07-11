// Generates public/og-image.png (1200x630) for Open Graph / Twitter cards.
// Zero dependencies: rasterizes a lattice motif + pixel-font text into an RGBA
// buffer and writes a minimal PNG (IHDR + zlib IDAT + IEND) by hand.
// Run: node scripts/generate-og-image.mjs

import { deflateSync } from 'node:zlib';
import { writeFileSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const W = 1200;
const H = 630;
const px = new Uint8Array(W * H * 4);

// ── palette (matches the demo's dark theme) ──────────────────────────────────
const BG = [0x07, 0x17, 0x0f];
const DOT = [0x2b, 0x4a, 0x3a];
const DOT_SHORT = [0xff, 0xad, 0x64];
const ACCENT = [0x4c, 0xe1, 0xb4];
const TEXT = [0xe9, 0xff, 0xf1];
const MUTED = [0xae, 0xd8, 0xbd];

function set(x, y, [r, g, b], alpha = 1) {
  if (x < 0 || x >= W || y < 0 || y >= H) return;
  const i = (y * W + x) * 4;
  px[i] = Math.round(px[i] * (1 - alpha) + r * alpha);
  px[i + 1] = Math.round(px[i + 1] * (1 - alpha) + g * alpha);
  px[i + 2] = Math.round(px[i + 2] * (1 - alpha) + b * alpha);
  px[i + 3] = 255;
}

function fillRect(x0, y0, w, h, color, alpha = 1) {
  for (let y = y0; y < y0 + h; y += 1) for (let x = x0; x < x0 + w; x += 1) set(x, y, color, alpha);
}

function fillCircle(cx, cy, r, color, alpha = 1) {
  for (let y = Math.floor(cy - r); y <= cy + r; y += 1) {
    for (let x = Math.floor(cx - r); x <= cx + r; x += 1) {
      const d = Math.hypot(x - cx, y - cy);
      if (d <= r) set(x, y, color, alpha);
      else if (d <= r + 1) set(x, y, color, alpha * (r + 1 - d)); // 1px soft edge
    }
  }
}

function line(x0, y0, x1, y1, width, color) {
  const steps = Math.ceil(Math.hypot(x1 - x0, y1 - y0));
  for (let i = 0; i <= steps; i += 1) {
    const t = i / steps;
    fillCircle(x0 + (x1 - x0) * t, y0 + (y1 - y0) * t, width / 2, color);
  }
}

// ── 5×7 pixel font ───────────────────────────────────────────────────────────
const FONT = {
  A: ['01110', '10001', '10001', '11111', '10001', '10001', '10001'],
  B: ['11110', '10001', '10001', '11110', '10001', '10001', '11110'],
  C: ['01110', '10001', '10000', '10000', '10000', '10001', '01110'],
  D: ['11110', '10001', '10001', '10001', '10001', '10001', '11110'],
  E: ['11111', '10000', '10000', '11110', '10000', '10000', '11111'],
  F: ['11111', '10000', '10000', '11110', '10000', '10000', '10000'],
  G: ['01110', '10001', '10000', '10111', '10001', '10001', '01110'],
  I: ['11111', '00100', '00100', '00100', '00100', '00100', '11111'],
  L: ['10000', '10000', '10000', '10000', '10000', '10000', '11111'],
  M: ['10001', '11011', '10101', '10101', '10001', '10001', '10001'],
  N: ['10001', '11001', '10101', '10011', '10001', '10001', '10001'],
  O: ['01110', '10001', '10001', '10001', '10001', '10001', '01110'],
  P: ['11110', '10001', '10001', '11110', '10000', '10000', '10000'],
  Q: ['01110', '10001', '10001', '10001', '10101', '10010', '01101'],
  R: ['11110', '10001', '10001', '11110', '10100', '10010', '10001'],
  S: ['01111', '10000', '10000', '01110', '00001', '00001', '11110'],
  T: ['11111', '00100', '00100', '00100', '00100', '00100', '00100'],
  U: ['10001', '10001', '10001', '10001', '10001', '10001', '01110'],
  Y: ['10001', '10001', '01010', '00100', '00100', '00100', '00100'],
  '-': ['00000', '00000', '00000', '11111', '00000', '00000', '00000'],
  ' ': ['00000', '00000', '00000', '00000', '00000', '00000', '00000']
};

function drawText(text, x0, y0, scale, color) {
  let x = x0;
  for (const ch of text) {
    const glyph = FONT[ch] ?? FONT[' '];
    for (let gy = 0; gy < 7; gy += 1) {
      for (let gx = 0; gx < 5; gx += 1) {
        if (glyph[gy][gx] === '1') fillRect(x + gx * scale, y0 + gy * scale, scale, scale, color);
      }
    }
    x += 6 * scale;
  }
  return x;
}

// ── compose ──────────────────────────────────────────────────────────────────
fillRect(0, 0, W, H, BG);

// lattice motif, right-hand side, basis (60,12) & (20,52) around center (880,315)
const CX = 880;
const CY = 315;
const B1 = { x: 60, y: 12 };
const B2 = { x: 20, y: 52 };
for (let i = -8; i <= 8; i += 1) {
  for (let j = -8; j <= 8; j += 1) {
    const x = CX + i * B1.x + j * B2.x;
    const y = CY - (i * B1.y + j * B2.y);
    if (x < 620 || x > W - 20 || y < 20 || y > H - 20) continue;
    const short = Math.hypot(x - CX, y - CY) < 110;
    fillCircle(x, y, short ? 5 : 4, short ? DOT_SHORT : DOT, short ? 0.95 : 0.8);
  }
}
line(CX, CY, CX + B1.x * 2, CY - B1.y * 2, 6, ACCENT);
line(CX, CY, CX + B2.x * 2, CY - B2.y * 2, 6, ACCENT);
fillCircle(CX, CY, 8, ACCENT);

// text block, left-hand side
drawText('CRYPTO LAB', 70, 150, 5, ACCENT);
drawText('FALCON', 70, 230, 14, TEXT);
drawText('SEAL', 70, 345, 14, TEXT);
drawText('POST-QUANTUM SIGNATURES', 70, 480, 4, MUTED);
drawText('NTRU LATTICES - FN-DSA', 70, 525, 4, MUTED);

// ── encode PNG ───────────────────────────────────────────────────────────────
const CRC_TABLE = new Int32Array(256).map((_, n) => {
  let c = n;
  for (let k = 0; k < 8; k += 1) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  return c;
});

function crc32(buf) {
  let c = -1;
  for (const b of buf) c = CRC_TABLE[(c ^ b) & 0xff] ^ (c >>> 8);
  return (c ^ -1) >>> 0;
}

function chunk(type, data) {
  const out = Buffer.alloc(12 + data.length);
  out.writeUInt32BE(data.length, 0);
  out.write(type, 4, 'ascii');
  data.copy(out, 8);
  out.writeUInt32BE(crc32(out.subarray(4, 8 + data.length)), 8 + data.length);
  return out;
}

const ihdr = Buffer.alloc(13);
ihdr.writeUInt32BE(W, 0);
ihdr.writeUInt32BE(H, 4);
ihdr[8] = 8; // bit depth
ihdr[9] = 6; // RGBA
const raw = Buffer.alloc(H * (1 + W * 4));
for (let y = 0; y < H; y += 1) {
  raw[y * (1 + W * 4)] = 0; // filter: none
  Buffer.from(px.buffer, y * W * 4, W * 4).copy(raw, y * (1 + W * 4) + 1);
}
const png = Buffer.concat([
  Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
  chunk('IHDR', ihdr),
  chunk('IDAT', deflateSync(raw, { level: 9 })),
  chunk('IEND', Buffer.alloc(0))
]);

const outPath = join(dirname(fileURLToPath(import.meta.url)), '..', 'public', 'og-image.png');
mkdirSync(dirname(outPath), { recursive: true });
writeFileSync(outPath, png);
console.log(`Wrote ${outPath} (${(png.length / 1024).toFixed(1)} kB)`);
