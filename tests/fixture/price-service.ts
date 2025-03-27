import { serve } from "@hono/node-server";
import { Hono } from "hono";

export function startTokenPriceService() {
  const priceService = new Hono();
  priceService.get("/api/v3/simple/price", (c) => {
    return c.json({
      nillion: {
        usd: 1,
      },
    });
  });
  serve({
    port: 59123,
    fetch: priceService.fetch,
  });
}
