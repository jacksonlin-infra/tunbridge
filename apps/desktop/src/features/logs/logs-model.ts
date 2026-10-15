import type { MihomoLogEntry, MihomoLogLevel, MihomoLogPage } from "../../types";

export const MAX_VISIBLE_LOGS = 1_000;

export interface LogBuffer {
  engineGeneration: string;
  cursor: number;
  oldestSequence: number;
  dropped: boolean;
  items: MihomoLogEntry[];
}

export const emptyLogBuffer = (): LogBuffer => ({
  engineGeneration: "",
  cursor: 0,
  oldestSequence: 1,
  dropped: false,
  items: [],
});

export const mergeLogPage = (current: LogBuffer, page: MihomoLogPage): LogBuffer => {
  const generationChanged = current.engineGeneration !== page.engineGeneration;
  const base = generationChanged ? emptyLogBuffer() : current;
  const retained = base.items.filter((item) => item.sequence >= page.oldestSequence);
  const bySequence = new Map(retained.map((item) => [item.sequence, item]));
  for (const item of page.items) bySequence.set(item.sequence, item);
  const items = [...bySequence.values()]
    .sort((left, right) => left.sequence - right.sequence)
    .slice(-MAX_VISIBLE_LOGS);
  const cursor = page.items.length
    ? page.items[page.items.length - 1].sequence
    : base.cursor;
  return {
    engineGeneration: page.engineGeneration,
    cursor,
    oldestSequence: page.oldestSequence,
    dropped: base.dropped
      || (generationChanged && page.oldestSequence > 1)
      || (!generationChanged && base.cursor > 0 && page.oldestSequence > base.cursor + 1),
    items,
  };
};

export const filterLogs = (
  items: MihomoLogEntry[],
  level: MihomoLogLevel | "all",
  query: string,
  order: "asc" | "desc",
): MihomoLogEntry[] => {
  const normalized = query.trim().toLocaleLowerCase();
  const filtered = items.filter((item) =>
    (level === "all" || item.level === level)
    && (!normalized || item.message.toLocaleLowerCase().includes(normalized)),
  );
  return order === "asc" ? filtered : [...filtered].reverse();
};
