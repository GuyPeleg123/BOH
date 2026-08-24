import { useEffect, useState } from "react";

/**
 * Force a re-render at most once every `intervalMs` so a high-frequency store
 * doesn't make a component flicker. The component still reads the latest store
 * state on each render — this hook only paces *when* renders happen.
 *
 * Use for components that show summary numbers (counters, rates) where seeing
 * an exact instantaneous value at 15 Hz is worse than a calm 1 Hz update.
 */
export function useStableTick(intervalMs: number): number {
  const [tick, setTick] = useState(0);
  useEffect(() => {
    const id = setInterval(() => setTick((t) => t + 1), intervalMs);
    return () => clearInterval(id);
  }, [intervalMs]);
  return tick;
}
