import dockerCompose from "docker-compose";
import type { TestProject } from "vitest/node";
import { NilauthClient } from "#/nilauth";

const MAX_RETRIES = 300;
const composeOptions = {
  cwd: "./docker",
};

export async function setup(_project: TestProject) {
  console.log("🚀 Starting containers...");
  try {
    // Check if containers are already running
    const psResult = await dockerCompose.ps(composeOptions);
    const allServicesUp =
      psResult.data.services?.length > 0 &&
      psResult.data.services.every((service) => service.state?.includes("Up"));

    if (allServicesUp) {
      console.log("✅ Containers already running, skipping startup.");
      return;
    }

    await dockerCompose.upAll({ cwd: "./docker" });
    const dockerStatus = async () => {
      const result = await dockerCompose.ps({ cwd: "./docker" });
      return (
        result.data.services?.length > 0 &&
        result.data.services.every((service) => service.state.includes("Up"))
      );
    };
    await retryProcess(dockerStatus, "Error starting containers");

    // Although Docker is active, nilauth could be initializing. We'll wait for it to respond to our requests.
    const nilAuth = new NilauthClient("http://127.0.0.1:30921");
    const nilAuthIsUp = async () => {
      try {
        return (await nilAuth.health()) === "OK";
      } catch (_) {
        return false;
      }
    };
    await retryProcess(nilAuthIsUp, "Error starting nilauth container");

    console.log("✅ Containers started successfully.");
  } catch (error) {
    console.error("❌ Error starting containers: ", error);
    process.exit(1);
  }
}

async function retryProcess(
  f: () => Promise<boolean>,
  msg: string,
): Promise<void> {
  let retry = 0;
  for (; retry < MAX_RETRIES; retry++) {
    if (await f()) return;
    await new Promise((f) => setTimeout(f, 200));
  }
  console.error(`❌ ${msg}: timeout`);
  process.exit(1);
}

export async function teardown() {
  // Skip teardown if KEEP_INFRA environment variable is set
  if (process.env.KEEP_INFRA === "true") {
    console.log("🔄 Keeping infrastructure running as KEEP_INFRA=true");
    return;
  }

  console.log("🛑 Removing containers...");
  try {
    await dockerCompose.downAll({ cwd: "./docker" });
    console.log("✅ Containers removed successfully.");
  } catch (error) {
    console.error("❌ Error removing containers: ", error);
    process.exit(1);
  }
}
