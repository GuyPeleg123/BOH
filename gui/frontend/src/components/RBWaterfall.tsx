import { useEffect, useRef } from "react";
import { useStore } from "../lib/store";
import { rntiColor, powerColor } from "../lib/color";

interface Props {
  mode: "alloc" | "power";
  direction: "dl" | "ul";
}

const REDRAW_INTERVAL_MS = 200; // 5 Hz max; the underlying data updates faster

export function RBWaterfall({ mode, direction }: Props) {
  const { state } = useStore();
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const wrapRef = useRef<HTMLDivElement>(null);
  const sizeRef = useRef({ w: 0, h: 0 });
  const lastDrawRef = useRef(0);
  const pendingRafRef = useRef<number | null>(null);

  useEffect(() => {
    if (!wrapRef.current) return;
    const ro = new ResizeObserver((entries) => {
      for (const e of entries) {
        const cr = e.contentRect;
        sizeRef.current = { w: Math.floor(cr.width), h: Math.floor(cr.height) };
        scheduleDraw(true);
      }
    });
    ro.observe(wrapRef.current);
    return () => ro.disconnect();
  }, []);

  useEffect(() => { scheduleDraw(false); }, [state.sfHistory, state.cell, mode, direction]);

  function scheduleDraw(force: boolean) {
    const now = performance.now();
    const since = now - lastDrawRef.current;
    if (force || since >= REDRAW_INTERVAL_MS) {
      lastDrawRef.current = now;
      draw();
      return;
    }
    if (pendingRafRef.current != null) return;
    const delay = REDRAW_INTERVAL_MS - since;
    pendingRafRef.current = window.setTimeout(() => {
      pendingRafRef.current = null;
      lastDrawRef.current = performance.now();
      draw();
    }, delay);
  }

  function draw() {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const { w, h } = sizeRef.current;
    if (w < 4 || h < 4) return;
    if (canvas.width !== w || canvas.height !== h) {
      canvas.width = w;
      canvas.height = h;
    }
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    ctx.fillStyle = "#0b0e14";
    ctx.fillRect(0, 0, w, h);

    const history = state.sfHistory;
    if (history.length === 0) {
      ctx.fillStyle = "#5b6478";
      ctx.font = "12px ui-sans-serif";
      ctx.textAlign = "center";
      ctx.fillText("waiting for subframes…", w / 2, h / 2);
      return;
    }

    const nprb = (state.cell?.nof_prb ?? history[0].rb_dl.length) || 50;
    const rowH = Math.max(1, Math.floor(h / Math.min(history.length, h)));
    const colW = Math.max(1, w / nprb);

    const visible = history.slice(-Math.floor(h / rowH));
    for (let i = 0; i < visible.length; i++) {
      const sf = visible[i];
      const y = h - (visible.length - i) * rowH;
      if (mode === "alloc") {
        const map = direction === "dl" ? sf.rb_dl : sf.rb_ul;
        for (let p = 0; p < map.length; p++) {
          const r = map[p];
          if (!r) continue;
          ctx.fillStyle = rntiColor(r);
          ctx.fillRect(Math.floor(p * colW), y, Math.ceil(colW), rowH);
        }
      } else {
        const min = sf.pwr_min ?? -100;
        const max = sf.pwr_max ?? -50;
        for (let p = 0; p < sf.pwr_dl.length; p++) {
          ctx.fillStyle = powerColor(sf.pwr_dl[p], min, max);
          ctx.fillRect(Math.floor(p * colW), y, Math.ceil(colW), rowH);
        }
      }
    }

    // PRB grid hints (vertical lines every 10 PRB)
    ctx.strokeStyle = "rgba(255,255,255,0.04)";
    ctx.lineWidth = 1;
    for (let p = 10; p < nprb; p += 10) {
      const x = Math.floor(p * colW) + 0.5;
      ctx.beginPath();
      ctx.moveTo(x, 0);
      ctx.lineTo(x, h);
      ctx.stroke();
    }
  }

  return (
    <div ref={wrapRef} className="relative w-full h-full overflow-hidden bg-bg rounded">
      <canvas ref={canvasRef} className="block w-full h-full" />
    </div>
  );
}
