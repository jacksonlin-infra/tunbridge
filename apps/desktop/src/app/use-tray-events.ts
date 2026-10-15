import { useEffect } from "react";
import { invoke, listen } from "../bridge";
import { trayDestination, type NavigationTarget } from "./navigation";

interface TrayEventHandlers {
  navigate: (target: NavigationTarget) => void;
  exitFailed: () => void;
  exitConfirm: () => void;
}

/** Subscribes to the native tray and quit events once for the app lifetime. */
export function useTrayEvents(handlers: TrayEventHandlers) {
  useEffect(() => {
    let disposed = false;
    let unlistenNavigate: (() => void) | undefined;
    let unlistenExitFailed: (() => void) | undefined;
    let unlistenExitConfirm: (() => void) | undefined;
    const navigateFromTray = (destination: string | null) => {
      if (disposed) return;
      const target = trayDestination(destination);
      if (target) handlers.navigate(target);
    };
    void listen<string>("tunbridge:tray-navigate", ({ payload }) => {
      navigateFromTray(payload);
      // A native pending value makes navigation reliable even if the menu was
      // clicked while the WebView listener was still being registered.
      void invoke<string | null>("take_pending_tray_navigation")
        .then(() => undefined)
        .catch(() => undefined);
    }).then(async (unlisten) => {
      if (disposed) {
        unlisten();
        return;
      }
      unlistenNavigate = unlisten;
      try {
        navigateFromTray(await invoke<string | null>("take_pending_tray_navigation"));
      } catch {
        // The tray is an optional integration in the browser development mock.
      }
    });
    void listen<string>("tunbridge:tray-exit-failed", () => {
      if (!disposed) handlers.exitFailed();
    }).then((unlisten) => {
      if (disposed) unlisten();
      else unlistenExitFailed = unlisten;
    });
    void listen<null>("tunbridge:exit-confirm", () => {
      if (!disposed) handlers.exitConfirm();
    }).then((unlisten) => {
      if (disposed) unlisten();
      else unlistenExitConfirm = unlisten;
    });
    return () => {
      disposed = true;
      unlistenNavigate?.();
      unlistenExitFailed?.();
      unlistenExitConfirm?.();
    };
    // Subscribed once: the handlers only call stable React state setters.
  }, []);
}
