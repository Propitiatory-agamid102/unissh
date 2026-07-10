import { createRoot } from "react-dom/client";

// vendored fonts (offline)
import "@fontsource/hanken-grotesk/400.css";
import "@fontsource/hanken-grotesk/500.css";
import "@fontsource/hanken-grotesk/600.css";
import "@fontsource/hanken-grotesk/700.css";
import "@fontsource/hanken-grotesk/800.css";
import "@fontsource/jetbrains-mono/400.css";
import "@fontsource/jetbrains-mono/500.css";
import "@fontsource/jetbrains-mono/600.css";
import "@fontsource/jetbrains-mono/700.css";

import "./theme/theme.css";
import "./i18n"; // initialize i18next before first render
import { ThemeProvider } from "./theme/ThemeProvider";
import { App } from "./App";

// NOTE: no StrictMode — components open real resources (PTY sessions, SFTP, tunnels)
// in effects, and StrictMode's dev double-invoke would open them twice.
createRoot(document.getElementById("root")!).render(
  <ThemeProvider>
    <App />
  </ThemeProvider>,
);
