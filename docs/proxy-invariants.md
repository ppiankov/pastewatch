# Proxy Invariants

PR #25 is complete when these invariants are guarded by green tests. A review
finding is a merge blocker only if it violates one of these invariants; new edge
ideas outside this list should be logged as future work, not used to keep the PR
open.

1. Mutate bytes only on `.critical` matches; never infer secret status from shape alone.
   Guard: `ProxyStreamRedactionTests.testCriticalMatchMutatesStreamBytes`.

2. Ambiguous `.high`, `.medium`, and `.low` matches are never silently redacted and
   never silently passed. They pass byte-identically and emit an advisory with a
   suggested config action.
   Guard: `ProxyStreamRedactionTests.testAmbiguousMatchIsAdvisoryOnlyAndByteIdentical`.

3. Client disconnect anywhere produces clean bounded teardown with no leaked file
   descriptor, thread, or child process.
   Guard: `ProxyTimeoutTests.testSSEStreamRelayHardCeilingCancelsHangingTaskWithoutWritingHeaders`.

4. `stop()` returns within a bounded window and does not drop accepted audit writes.
   Guard: `ProxyTimeoutTests.testNonStreamingTaskWaitReturnsOnShutdownWithoutFullTimeout`
   and `ProxyAlertTests.testAlertInjectionSkippedAuditLineForNonJSONBufferedResponse`.

5. Partial sends and saturated admission never silently truncate client output.
   Guard: `ProxyRealServerTests.testAdmissionCapRejectsFifthConcurrentConnection`.

6. Idle or hung upstream work is closed within the configured deadline.
   Guard: `ProxyTimeoutTests.testSSEStreamRelayHardCeilingCancelsHangingTaskWithoutWritingHeaders`.
