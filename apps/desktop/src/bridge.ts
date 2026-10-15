import {
  invoke as tauriInvoke,
  type InvokeArgs,
  type InvokeOptions,
} from "@tauri-apps/api/core";
import {
  listen as tauriListen,
  type EventCallback,
  type Options,
  type UnlistenFn,
} from "@tauri-apps/api/event";
import { mockInvoke, mockListen } from "./dev-mock";

export const devMockEnabled =
  import.meta.env.DEV && import.meta.env.VITE_TUNBRIDGE_DEV_MOCK === "1";

export function invoke<T>(
  command: string,
  args?: InvokeArgs,
  options?: InvokeOptions,
): Promise<T> {
  if (devMockEnabled) {
    return mockInvoke<T>(command, args);
  }
  if (options !== undefined) {
    return tauriInvoke<T>(command, args, options);
  }
  if (args !== undefined) {
    return tauriInvoke<T>(command, args);
  }
  return tauriInvoke<T>(command);
}

export function listen<T>(
  event: string,
  handler: EventCallback<T>,
  options?: Options,
): Promise<UnlistenFn> {
  if (devMockEnabled) {
    void options;
    return Promise.resolve(mockListen(event, handler as Parameters<typeof mockListen>[1]));
  }
  return tauriListen(event, handler, options);
}
