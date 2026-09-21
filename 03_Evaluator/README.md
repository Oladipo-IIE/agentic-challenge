# Campus Crisis Agent Evaluator

**CONFIDENTIAL WHEN USED WITH HIDDEN GROUND TRUTH**

Requires Node.js 18 or later and no external packages.

```bash
node evaluator.js ground_truth.jsonl predictions.jsonl score.json
```

The evaluator writes a score out of 60, component scores, validation diagnostics and report-level issues. Student incident IDs are treated as cluster labels and never compared literally with hidden event IDs.

Run the included tests with:

```bash
node test_evaluator.js
```

Invalid JSON lines, duplicate report IDs and unknown report IDs are reported. Missing predictions receive no credit for the affected reports. A team must cover at least 80% of hidden reports to remain eligible, but the evaluator still produces a diagnostic score below that threshold.
