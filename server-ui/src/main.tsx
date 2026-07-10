import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import "@fontsource/hanken-grotesk/400.css";
import "@fontsource/hanken-grotesk/500.css";
import "@fontsource/hanken-grotesk/600.css";
import "@fontsource/hanken-grotesk/700.css";
import "@fontsource/hanken-grotesk/800.css";
import "@fontsource/jetbrains-mono/400.css";
import "@fontsource/jetbrains-mono/500.css";
import "@fontsource/jetbrains-mono/600.css";
import "@fontsource/jetbrains-mono/700.css";

import "./theme/global.css";
import "./i18n";
import { App } from "./App";
import { loadWasmProvider } from "./crypto/wasm-provider";

// Load the real rust-core crypto (wasm) in the background; keyset operations
// stay gracefully disabled until it resolves.
void loadWasmProvider();

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
