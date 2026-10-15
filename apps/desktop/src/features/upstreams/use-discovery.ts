import { useState } from "react";
import { invoke } from "../../bridge";
import { normalizeProxyError } from "../../local-proxy";
import type {
  DiscoveryResponse,
  DiscoveryWarningCode,
  LocalProxyCandidate,
  ProxyError,
  ProxyTestResponse,
} from "../../types";

const discoverUpstreams = (): Promise<DiscoveryResponse> =>
  invoke<DiscoveryResponse>("discover_upstreams");

/** Tests a discovered listener before it is saved; never sends credentials. */
const testUpstream = (candidate: LocalProxyCandidate): Promise<ProxyTestResponse> =>
  invoke<ProxyTestResponse>("test_upstream", {
    input: { port: candidate.port, protocol: candidate.protocol },
  });

export interface CandidateTest {
  candidate: LocalProxyCandidate;
  result: ProxyTestResponse | null;
  error: ProxyError | null;
}

/** Bounded loopback discovery and a credential-free test of one listener. */
export function useDiscovery() {
  const [candidates, setCandidates] = useState<LocalProxyCandidate[]>([]);
  const [warningCodes, setWarningCodes] = useState<DiscoveryWarningCode[]>([]);
  const [discovering, setDiscovering] = useState(false);
  const [scannedAt, setScannedAt] = useState<number | null>(null);
  const [error, setError] = useState<ProxyError | null>(null);
  const [testing, setTesting] = useState(false);
  const [candidateTest, setCandidateTest] = useState<CandidateTest | null>(null);

  const runDiscovery = async () => {
    if (discovering) return;
    setDiscovering(true);
    setWarningCodes([]);
    setError(null);
    try {
      const response = await discoverUpstreams();
      setCandidates(response.candidates);
      setWarningCodes(response.warningCodes);
    } catch (discoveryError) {
      setCandidates([]);
      setError(normalizeProxyError(discoveryError));
    } finally {
      setScannedAt(Date.now());
      setDiscovering(false);
    }
  };

  const testCandidate = async (candidate: LocalProxyCandidate) => {
    if (testing) return;
    setTesting(true);
    setCandidateTest({ candidate, result: null, error: null });
    try {
      const result = await testUpstream(candidate);
      setCandidateTest({ candidate, result, error: null });
    } catch (testError) {
      setCandidateTest({ candidate, result: null, error: normalizeProxyError(testError) });
    } finally {
      setTesting(false);
    }
  };

  return {
    candidates,
    warningCodes,
    discovering,
    scanned: scannedAt !== null,
    scannedAt,
    error,
    testing,
    candidateTest,
    clearCandidateTest: () => setCandidateTest(null),
    runDiscovery,
    testCandidate,
  };
}

export type DiscoveryApi = ReturnType<typeof useDiscovery>;
