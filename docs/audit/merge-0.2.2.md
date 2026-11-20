# Merge of server 0.2.2 into audit PR (2026-11-20)

This PR now includes default branch 0.2.2 while retaining the independent audited fixes and their tests. The merge was reconstructed against the common 0.2.1 base with three-way line changes. Where upstream and audit edits collided, the audited changes were preferred and overlapping upstream hunks were not blindly stacked; unaffected 0.2.2 changes were preserved. No default-branch file was modified.

The exact resulting diff is in PR #1. Newly added 0.2.2 features and affected paths require full CI validation against this merge commit. In particular, check TLS identity, multi-node synchronization, restricted destination routing, password/session state, notifications, SQLite transactions, quota accounting and subscriptions. This note does NOT claim conflict resolution is automatically functionally correct. Any failing test must be fixed before approval.

Previously passing 273 Python tests on both supported versions, 56 live-core end-to-end checks and 45 install checks belong to commit 9310fdc1493a3f2cc3e7f151be9831a1c5475d24 (run 44729199433), not to the new merge.

## 修复 0.2.2 合并后的服务初始化死锁

0.2.2 在 `cores.py` 新增普通 `_apply_lock = threading.Lock()` 覆盖了审计的 `RLock`。因为 `apply()` 与 `write_configs()` 同时受 `@_serial_apply` 修饰，前者调用后者时在同一线程再次请求非可重入锁，造成 CI 安装运行在 `vps2vpn apply --force` 阶段停住。保留一个 `threading.RLock`，并在 `tests/test_apply_audit.py` 用独立线程与明确截止时间回归验证同线程重入、失败时不无限挂起。本次修复之后的安装验收仍必须重新跑完整 CI。
