import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
// Global styles first so feature stylesheets imported by components override them.
import "./styles.css";
import "./ui/appearance.css";
import App from "./App";

const root = document.getElementById("root");
if (!root) throw new Error("TunBridge root element is missing");

createRoot(root).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
