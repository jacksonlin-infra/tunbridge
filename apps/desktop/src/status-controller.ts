import type {
  DesktopError,
  DesktopErrorCode,
  DesktopStatus,
  StatusViewState,
} from "./types";

export type StatusLoader = () => Promise<DesktopStatus>;
export type StateListener = (state: StatusViewState) => void;

const errorMessages: Record<DesktopErrorCode, string> = {
  service_unavailable: "The TunBridge service is unavailable.",
  service_identity_failed: "The TunBridge service identity could not be verified.",
  service_protocol_error: "The TunBridge service returned an invalid response.",
  service_rejected: "The TunBridge service rejected the status request.",
};

const parseDesktopError = (value: unknown): DesktopError | undefined => {
  if (!value || typeof value !== "object") return undefined;
  const candidate = value as Partial<DesktopError>;
  if (
    typeof candidate.code !== "string" ||
    !(candidate.code in errorMessages) ||
    typeof candidate.retryable !== "boolean"
  ) {
    return undefined;
  }
  const code = candidate.code as DesktopErrorCode;
  return { code, safeMessage: errorMessages[code], retryable: candidate.retryable };
};

const safeUnknownError = (): DesktopError => ({
  code: "service_protocol_error",
  safeMessage: "The TunBridge service returned an invalid response.",
  retryable: false,
});

const previousStatus = (state: StatusViewState): DesktopStatus | undefined => {
  if (state.kind === "ready") return state.status;
  if (state.kind === "loading" || state.kind === "failure") return state.previous;
  return undefined;
};

export class StatusController {
  private state: StatusViewState = { kind: "boot" };
  private generation = 0;
  private inFlightGeneration: number | undefined;
  private visible = true;

  constructor(
    private readonly load: StatusLoader,
    private readonly publish: StateListener,
    private readonly now: () => number = Date.now,
  ) {}

  snapshot(): StatusViewState {
    return this.state;
  }

  setVisible(visible: boolean): void {
    this.visible = visible;
  }

  invalidate(): void {
    this.generation += 1;
    this.setState({ kind: "boot" });
  }

  async refresh(): Promise<boolean> {
    if (!this.visible || this.inFlightGeneration === this.generation) return false;

    const generation = this.generation;
    this.inFlightGeneration = generation;
    const previous = previousStatus(this.state);
    this.setState({ kind: "loading", ...(previous ? { previous } : {}) });
    try {
      const status = await this.load();
      if (generation !== this.generation) return false;
      this.setState({ kind: "ready", status, refreshedAt: this.now() });
      return true;
    } catch (error: unknown) {
      if (generation !== this.generation) return false;
      const parsedError = parseDesktopError(error);
      this.setState({
        kind: "failure",
        error: parsedError ?? safeUnknownError(),
        ...(previous ? { previous } : {}),
        failedAt: this.now(),
      });
      return true;
    } finally {
      if (this.inFlightGeneration === generation) {
        this.inFlightGeneration = undefined;
      }
    }
  }

  private setState(state: StatusViewState): void {
    this.state = state;
    this.publish(state);
  }
}
