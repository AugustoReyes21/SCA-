import express from "express";
import { join, normalize } from "node:path";
import { fileURLToPath } from "node:url";
import { getDemoPackage, scanPackageJson } from "./scaEngine.js";
import { isSnykConfigured, scanPackageJsonWithSnyk } from "./snykProvider.js";

const __dirname = fileURLToPath(new URL(".", import.meta.url));
const publicDir = normalize(join(__dirname, "..", "public"));
const preferredPort = Number.parseInt(process.env.PORT || "3000", 10);
const host = process.env.HOST || "0.0.0.0";
const app = express();
let activeServer;

app.use(express.json({ limit: "1mb" }));

app.get("/api/health", (_request, response) => {
  response.json({ status: "ok", app: "SCA Dashboard Node + Express" });
});

app.get("/api/demo-package", (_request, response) => {
  response.json({ packageJson: getDemoPackage() });
});

app.get("/api/providers", (_request, response) => {
  response.json({
    defaultProvider: isSnykConfigured() ? "snyk" : "demo",
    providers: {
      demo: {
        configured: true,
        name: "Motor demo local"
      },
      snyk: {
        configured: isSnykConfigured(),
        name: "Snyk CLI",
        requiredEnv: "SNYK_TOKEN",
        strategy: "package-lock-auto-detect-with-node-modules-fallback"
      }
    }
  });
});

app.post("/api/scan", async (request, response, next) => {
  try {
    const provider = request.body.provider || "auto";
    const shouldUseSnyk =
      provider === "snyk" || (provider === "auto" && isSnykConfigured());
    const report = shouldUseSnyk
      ? await scanPackageJsonWithSnyk(request.body.packageJson)
      : scanPackageJson(request.body.packageJson);

    response.json(report);
  } catch (error) {
    next(error);
  }
});

app.use(express.static(publicDir));

app.use((_request, response) => {
  response.status(404).json({ error: "Recurso no encontrado" });
});

app.use((error, _request, response, _next) => {
  const message =
    error instanceof SyntaxError
      ? "El cuerpo de la solicitud no es JSON valido."
      : error.message || "Error inesperado";

  response.status(400).json({ error: message });
});

listenWithFallback(preferredPort);
setupGracefulShutdown();

function listenWithFallback(port) {
  activeServer = app.listen(port, host, () => {
    console.log(`SCA Dashboard disponible en http://${host}:${port}`);
  });

  activeServer.once("error", (error) => {
    if (error.code === "EADDRINUSE" && port < preferredPort + 20) {
      listenWithFallback(port + 1);
      return;
    }

    throw error;
  });
}

function setupGracefulShutdown() {
  const shutdown = (signal) => {
    console.log(`Recibido ${signal}. Cerrando servidor...`);

    if (!activeServer) {
      process.exit(0);
    }

    activeServer.close(() => {
      process.exit(0);
    });
  };

  process.once("SIGINT", shutdown);
  process.once("SIGTERM", shutdown);
}
