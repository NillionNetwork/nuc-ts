import dockerCompose from "docker-compose";

export async function setup() {
  console.log("🚀 Starting containers...");
  try {
    await dockerCompose.upAll({ cwd: "." });
    // This gives time that all services are up
    await new Promise((f) => setTimeout(f, 2000));
    console.log("✅ Containers started successfully.");
  } catch (error) {
    console.error("❌ Error starting containers: ", error);
    process.exit(1);
  }
}

export async function teardown() {
  console.log("🛑 Removing containers...");
  try {
    await dockerCompose.downAll({ cwd: "." });
    console.log("✅ Containers removed successfully.");
  } catch (error) {
    console.error("❌ Error removing containers: ", error);
    process.exit(1);
  }
}
