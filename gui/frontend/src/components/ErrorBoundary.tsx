import React from "react";

// Kiosk safety net. Any render/lifecycle exception below this boundary would
// otherwise unmount the whole React tree and leave a permanent blank screen on
// an unattended appliance (Firefox --kiosk, nobody to reload). We show a minimal
// notice and auto-reload so the box heals itself without a human.
interface State {
  error: Error | null;
}

export class ErrorBoundary extends React.Component<{ children: React.ReactNode }, State> {
  state: State = { error: null };
  private timer: number | null = null;

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  componentDidCatch(error: Error) {
    // eslint-disable-next-line no-console
    console.error("ErrorBoundary caught:", error);
    // Auto-recover: a single malformed frame should not wedge the kiosk forever.
    if (this.timer == null) {
      this.timer = window.setTimeout(() => window.location.reload(), 5000);
    }
  }

  componentWillUnmount() {
    if (this.timer != null) window.clearTimeout(this.timer);
  }

  render() {
    if (this.state.error) {
      return (
        <div className="flex flex-col items-center justify-center h-screen gap-3 bg-bg text-muted">
          <span className="text-bad text-sm">The dashboard hit an error and is reloading…</span>
          <span className="text-[11px] font-mono text-muted max-w-md truncate px-4">
            {String(this.state.error?.message ?? this.state.error)}
          </span>
        </div>
      );
    }
    return this.props.children;
  }
}
