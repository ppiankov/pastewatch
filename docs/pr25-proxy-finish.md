# PR 25 Proxy Finish

The proxy finish criteria are defined in `docs/proxy-invariants.md`. Findings are
bucketed against that invariant set:

- Bucket (a), structurally obsolete under the bounded-cap model: WO-160, WO-203,
  WO-210, WO-245, WO-247, WO-253, WO-255, WO-257, WO-261, WO-264, WO-266, WO-307,
  WO-308, WO-314, WO-318.
- Bucket (b), still-real lifecycle or send behavior covered by invariant tests:
  WO-207, WO-209, WO-215, WO-223, WO-226, WO-229, WO-321, WO-322, WO-330.
- Bucket (c), redaction policy covered by critical-only mutation plus advisory
  handling: WO-316, WO-320, WO-324.

No WO in the WO-307..318 or EPIPE/concurrency cluster should be closed without a
bucket citation and the guarding test or production invariant named in the closure
note.
