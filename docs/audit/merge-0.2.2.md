# Merge of server 0.2.2 into audit PR (2026-11-20)

This PR now includes default branch 0.2.2 while retaining the independent audited fixes and their tests. The merge was reconstructed against the common 0.2.1 base with three-way line changes. Where upstream and audit edits collided, the audited changes were preferred and overlapping upstream hunks were not blindly stacked; unaffected 0.2.2 changes were preserved. No default-branch file was modified.

The exact resulting diff is in PR #1. Newly added 0.2.2 features and affected paths require full CI validation against this merge commit. In particular, check TLS identity, multi-node synchronization, restricted destination routing, password/session state, notifications, SQLite transactions, quota accounting and subscriptions. This note does NOT claim conflict resolution is automatically functionally correct. Any failing test must be fixed before approval.

Previously passing 273 Python tests on both supported versions, 56 live-core end-to-end checks and 45 install checks belong to commit 9310fdc1493a3f2cc3e7f151be9831a1c5475d24 (run 44729199433), not to the new merge.
