// Deterministic RNTI -> color mapping for the waterfall and tables.

export function rntiColor(rnti: number): string {
  if (rnti === 0) return "transparent";
  // Mix a few primes so colors don't cluster for adjacent RNTIs
  const h = (rnti * 2654435761) >>> 0;
  const hue = h % 360;
  const sat = 60 + ((h >>> 8) % 25);
  const lig = 50 + ((h >>> 16) % 15);
  return `hsl(${hue} ${sat}% ${lig}%)`;
}

export function powerColor(db: number, min: number, max: number): string {
  if (!isFinite(db)) return "transparent";
  const t = Math.max(0, Math.min(1, (db - min) / (max - min || 1)));
  // viridis-ish: dark blue -> teal -> green -> yellow
  const r = Math.floor(255 * Math.max(0, Math.min(1, 1.5 * t - 0.5)));
  const g = Math.floor(255 * Math.max(0, Math.min(1, t)));
  const b = Math.floor(255 * Math.max(0, Math.min(1, 1 - t)));
  return `rgb(${r},${g},${b})`;
}
