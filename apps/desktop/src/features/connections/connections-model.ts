import type { ConnectionView } from "../../types";

export type ConnectionSort =
  | "speed"
  | "download"
  | "upload"
  | "host"
  | "started";

const searchableText = (connection: ConnectionView): string =>
  [
    connection.host,
    connection.source,
    connection.destination,
    connection.processName,
    connection.rule,
    connection.rulePayload,
    ...connection.chains,
  ]
    .filter(Boolean)
    .join(" ")
    .toLocaleLowerCase();

export const filterAndSortConnections = (
  connections: ConnectionView[],
  query: string,
  sort: ConnectionSort,
): ConnectionView[] => {
  const normalizedQuery = query.trim().toLocaleLowerCase();
  const filtered = normalizedQuery
    ? connections.filter((connection) =>
        searchableText(connection).includes(normalizedQuery),
      )
    : [...connections];
  return filtered.sort((left, right) => {
    if (sort === "host") return left.host.localeCompare(right.host);
    if (sort === "started") return right.startedAt.localeCompare(left.startedAt);
    const leftValue = sort === "download"
      ? left.downloadTotal
      : sort === "upload"
        ? left.uploadTotal
        : left.downloadBps + left.uploadBps;
    const rightValue = sort === "download"
      ? right.downloadTotal
      : sort === "upload"
        ? right.uploadTotal
        : right.downloadBps + right.uploadBps;
    return rightValue - leftValue || left.host.localeCompare(right.host);
  });
};

export const connectionRuleLabel = (connection: ConnectionView): string =>
  connection.rulePayload
    ? `${connection.rule}(${connection.rulePayload})`
    : connection.rule || "Match";
