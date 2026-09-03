// OpenCode-NGA plugin entry point. The fork's extensions/ loader does NOT
// auto-discover tools/*.ts; it discovers this plugin via package.json's `main`
// and registers the secguard_* tools here via the `server.tool` hook — the
// same mechanism as opencode/index.ts. Config (agent + permission) and context
// hooks stay in opencode.json and plugins/secguard-context.ts respectively.
import secguard_scan from "./tools/secguard_scan"
import secguard_index from "./tools/secguard_index"
import secguard_plan from "./tools/secguard_plan"
import secguard_report from "./tools/secguard_report"
import secguard_status from "./tools/secguard_status"
import secguard_db from "./tools/secguard_db"
import secguard_schema from "./tools/secguard_schema"
import secguard_types from "./tools/secguard_types"
import secguard_metrics from "./tools/secguard_metrics"

export default {
  id: "secguard-clang",
  server: async () => ({
    tool: {
      secguard_scan,
      secguard_index,
      secguard_plan,
      secguard_report,
      secguard_status,
      secguard_db,
      secguard_schema,
      secguard_types,
      secguard_metrics,
    },
  }),
}
