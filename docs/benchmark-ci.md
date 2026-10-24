# Benchmark PR CI 使用说明

> `.github/workflows/pr-benchmark.yml` 在 PR 上自动校验 `examples/c-vuln-benchmark`，防止检测器改动导致误报回潮或候选计数漂移。

## 校验什么

- **FP=0 红线**（强制）：`validate-benchmark.py --allow-fn` 下，凡 `false positives > 0` 即 CI 红。
  这是 confirmed/auto-confirmed 侧的最大约束——auto-confirm 不能引入新误报。
- **候选数稳定**（隐含）：scan 的 `final_count` / `seed_count` 变化会在日志里可见；
  若某 PR 大幅改变候选数，reviewer 应人工核查。
- **FN 允许**：大量 expected-finding 依赖 AI 研判才能落 result.sarif；CI 无 LLM 环节，
  `--allow-fn` 跳过 FN 计数，只守 FP 红线。

## CI 红时本地复现

```bash
# 1. 构建本地 CLI
cd sgre
GOCACHE=$PWD/.tmpcache CGO_ENABLED=1 GOFLAGS=-mod=mod go build -buildvcs=false -o ../bin/secguard ./cmd/secguard
cd ..

# 2. 扫 benchmark
rm -rf /tmp/bench && mkdir -p /tmp/bench
cp -r examples/c-vuln-benchmark/src /tmp/bench/
cd /tmp/bench
<repo>/bin/secguard scan . --db /tmp/bench/sgre.db
SCAN_ID=$(ls .codeagent/secguard-clang/scans | grep -v latest | head -1)
<repo>/bin/secguard report --audit \
  --scan-id "$SCAN_ID" \
  --output-dir "/tmp/bench/.codeagent/secguard-clang/scans/$SCAN_ID" \
  --db /tmp/bench/sgre.db

# 3. 校验
python3 <repo>/examples/c-vuln-benchmark/scripts/validate-benchmark.py \
  --root /tmp/bench \
  --expected <repo>/examples/c-vuln-benchmark/expected-results.json \
  --allow-fn
```

## ground truth 维护纪律

- detector/filter/registry 任何改动若改变候选或 auto-confirm 集合，**必须同步**
  `examples/c-vuln-benchmark/expected-results.json`；
- 单测与 benchmark ground truth 若出现矛盾（如历史上的 IO-21），**在 PR 内裁定**，
  不允许两个"权威答案"长期并存；
- 腐烂的 ground truth 视为 P0 bug。