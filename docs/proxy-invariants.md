# Proxy Invariants

These invariants define the proxy streaming and shutdown behavior that must stay
guarded by tests. New edge ideas outside this list should be logged as follow-up
work unless they violate one of these invariants.

1. Mutate bytes only on `.critical` matches; never infer secret status from shape alone.
   Guard: `ProxyStreamRedactionTests.testCriticalMatchMutatesStreamBytes`.

2. Ambiguous `.high`, `.medium`, and `.low` matches are never silently redacted and
   never silently passed. They pass byte-identically and emit an advisory with a
   suggested config action.
   Guard: `ProxyStreamRedactionTests.testAmbiguousMatchIsAdvisoryOnlyAndByteIdentical`,
   `ProxyStreamRedactionTests.testMediumAndLowMatchesAreAdvisoryOnlyAndByteIdentical`,
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
   `ProxyHTTPRequestReadTests.testCurlResponseHeaderReaderRejectsEOFWithPartialHeaders`.
