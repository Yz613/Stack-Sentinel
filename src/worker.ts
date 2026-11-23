import handler from "vinext/server/fetch-handler";
import { runThreatWatchScan } from "./lib/threat-watch";

const worker = {
  fetch: handler.fetch,
  async scheduled(
    controller: ScheduledController,
    _env: unknown,
    ctx: ExecutionContext,
  ): Promise<void> {
    ctx.waitUntil(
      runThreatWatchScan("workspace:default", {
        trigger: "cron",
        cron: controller.cron,
      }).then(
        (res) => {
          console.log("[threat-watch-cron]", JSON.stringify({
            id: res.id,
            newIncidentsCount: res.newIncidentsCount,
            affectedReposCount: res.affectedReposCount,
            patchPlansCount: res.patchPlans.length,
          }));
        },
        (err) => {
          console.error("[threat-watch-cron] failed:", err);
        },
      ),
    );
  },
};

export default worker;
