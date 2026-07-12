# Proxy Invariants

These invariants define the proxy streaming and shutdown behavior that must stay
guarded by tests. New edge ideas outside this list should be logged as follow-up
work unless they violate one of these invariants.

1. Mutate proxy bytes only for deterministic secret classes and operator-approved
   custom rules; uncertain built-ins are advisory-only regardless of `--severity`.
   The `--severity` flag gates advisory reporting volume, not mutation.
   Guard: `ProxyStreamRedactionTests.testCriticalMatchMutatesStreamBytes`,
   `ProxyStreamRedactionTests.testHighBuiltInMatchIsAdvisoryOnlyAndByteIdentical`, and
   `ProxyStreamRedactionTests.testHighCustomRuleMatchMutatesStreamBytes`.

2. Advisory-only matches are never silently redacted. Matches at or above the
   configured advisory threshold pass byte-identically and emit an advisory with
   a custom-rule promotion path.
   Guard: `ProxyStreamRedactionTests.testSeverityControlsAdvisoryVolumeNotMutationSet`,
   and `ProxyStreamRedactionTests.testLinuxRelayRawStreamMediumAdvisoryIsByteIdentical`.

3. Client disconnect anywhere produces clean bounded teardown with no leaked file
   descriptor, thread, or child process.
   Guard: `ProxyTimeoutTests.testSSEStreamRelayClientDisconnectDuringDoneAlertReturnsBounded`,
   `ProxyStreamRedactionTests.testLinuxRelayStopsAfterClientEPIPEMidStream`, and
   `ProxyHTTPRequestReadTests.testSendAllReturnsFalseWhenPeerClosed`.

4. `stop()` returns within a bounded window and does not drop accepted audit writes.
   Guard: `ProxyTimeoutTests.testNonStreamingTaskWaitReturnsOnShutdownWithoutFullTimeout`
   and `ProxyAlertTests.testAlertInjectionSkippedAuditLineForNonJSONBufferedResponse`.
   Linux curl stop uses `ProxyServer.stop()` -> `CurlHTTPClient.cancelActiveProcesses()`;
   Guard: `ProxyTimeoutTests.testCurlCancelActiveProcessesTerminatesRegisteredProcess`.

5. Partial sends and saturated admission never silently truncate client output.
   Guard: `ProxyRealServerTests.testAdmissionCapRejectsFifthConcurrentConnection`,
   `ProxyRealServerTests.testAdmitConnectionAfterStopSendsHTTP503ToAcceptedSocket`,
   and `ProxyRealServerTests.testQueuedAdmissionAfterStopSendsHTTP503WhenSlotOpens`.

6. Idle or hung upstream work is closed within the configured deadline.
   Guard: `ProxyTimeoutTests.testSSEStreamRelayHardCeilingAfterHeadersSendsHTTP504`,
   `ProxyTimeoutTests.testSSEStreamRelayIdleTimeoutAfterHeadersSendsHTTP504`, and
   `ProxyTimeoutTests.testCurlStreamingHeaderTimeoutTerminatesProcess`.
   Malformed or truncated response headers must fail closed;
   Guard: `ProxyHTTPRequestReadTests.testCurlResponseHeaderReaderRejectsEOFWithPartialHeaders`.
   Linux curl subprocess output must also be drained while the child is running;
   Guard: `ProxyHTTPRequestReadTests.testCurlNonStreamingCollectionDrainsLargeProcessOutputBeforeWait`.
