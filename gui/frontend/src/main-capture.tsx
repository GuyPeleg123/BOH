import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import AppCapture from "./AppCapture";
import { ErrorBoundary } from "./components/ErrorBoundary";
import "./index.css";

// Kiosk last-resort handlers: on an unattended appliance an unhandled async
// rejection or error must never sit as a silent dead-end. Log them (the
// ErrorBoundary handles render-time recovery via reload).
window.addEventListener("unhandledrejection", (e) => {
  // eslint-disable-next-line no-console
  console.error("unhandledrejection:", e.reason);
});
window.addEventListener("error", (e) => {
  // eslint-disable-next-line no-console
  console.error("window error:", (e as ErrorEvent).error ?? (e as ErrorEvent).message);
});

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <ErrorBoundary>
      <BrowserRouter>
        <AppCapture />
      </BrowserRouter>
    </ErrorBoundary>
  </React.StrictMode>
);
