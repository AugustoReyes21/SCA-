import { execFile } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  buildScaReport,
  collectDependencies,
  parsePackageJson
} from "./scaEngine.js";

const __dirname = fileURLToPath(new URL(".", import.meta.url));
const snykBin = join(
  __dirname,
  "..",
  "node_modules",
  ".bin",
  process.platform === "win32" ? "snyk.cmd" : "snyk"
);
const npmBin = process.platform === "win32" ? "npm.cmd" : "npm";

export function isSnykConfigured() {
  return Boolean(getSnykToken());
}

export async function scanPackageJsonWithSnyk(input) {
  const snykToken = getSnykToken();

  if (!snykToken) {
    throw new Error(
      "Snyk no esta configurado. Define la variable de entorno SNYK_TOKEN para usar el proveedor real."
    );
  }

  validateSnykToken(snykToken);

  const packageJson = parsePackageJson(input);
  const dependencies = collectDependencies(packageJson);
  const workspace = await mkdtemp(join(tmpdir(), "sca-snyk-"));

  try {
    await writeFile(
      join(workspace, "package.json"),
      JSON.stringify(packageJson, null, 2),
      "utf8"
    );

    await createPackageLock(workspace, snykToken);
    const snykOutput = await runSnykWithRetry(workspace, snykToken);
    return normalizeSnykReport({
      packageJson,
      dependencies,
      snykOutput
    });
  } finally {
    await rm(workspace, { force: true, recursive: true });
  }
}

function getSnykToken() {
  return String(process.env.SNYK_TOKEN || "")
    .trim()
    .replace(/^Bearer\s+/i, "");
}

function validateSnykToken(token) {
  if (/[\r\n\t]/.test(token)) {
    throw new Error(
      "El SNYK_TOKEN contiene saltos de linea o tabulaciones. Vuelve a copiar solo el token, sin espacios ni texto extra."
    );
  }

  if (token.includes(" ")) {
    throw new Error(
      "El SNYK_TOKEN contiene espacios. Pega solamente el token de Snyk, no el texto completo de la pagina."
    );
  }
}

async function runSnykWithRetry(workspace, snykToken) {
  try {
    return await runSnyk(workspace, snykToken);
  } catch (error) {
    if (!String(error.message).includes("Missing node_modules folder")) {
      throw error;
    }

    await installDependencies(workspace, snykToken);
    return runSnyk(workspace, snykToken);
  }
}

function createPackageLock(workspace, snykToken) {
  const args = [
    "install",
    "--package-lock-only",
    "--ignore-scripts",
    "--legacy-peer-deps",
    "--no-audit",
    "--no-fund"
  ];

  return new Promise((resolve, reject) => {
    execFile(
      npmBin,
      args,
      {
        cwd: workspace,
        env: buildChildEnv(snykToken),
        maxBuffer: 20 * 1024 * 1024,
        timeout: 120_000
      },
      (error, stdout, stderr) => {
        if (!error) {
          resolve();
          return;
        }

        const detail = stderr || stdout || error.message;
        reject(
          new Error(
            `No se pudo resolver el arbol de dependencias con npm. Revisa que el package.json sea instalable: ${detail}`
          )
        );
      }
    );
  });
}

function installDependencies(workspace, snykToken) {
  const args = [
    "install",
    "--ignore-scripts",
    "--legacy-peer-deps",
    "--no-audit",
    "--no-fund"
  ];

  return new Promise((resolve, reject) => {
    execFile(
      npmBin,
      args,
      {
        cwd: workspace,
        env: buildChildEnv(snykToken),
        maxBuffer: 20 * 1024 * 1024,
        timeout: 180_000
      },
      (error, stdout, stderr) => {
        if (!error) {
          resolve();
          return;
        }

        const detail = stderr || stdout || error.message;
        reject(
          new Error(
            `Snyk pidio node_modules, pero npm no pudo instalar dependencias temporales: ${detail}`
          )
        );
      }
    );
  });
}

function runSnyk(workspace, snykToken) {
  const args = [
    "test",
    "--json",
    "--dev",
    "--strict-out-of-sync=false"
  ];

  return new Promise((resolve, reject) => {
    execFile(
      snykBin,
      args,
      {
        cwd: workspace,
        env: buildChildEnv(snykToken),
        maxBuffer: 20 * 1024 * 1024,
        timeout: 90_000
      },
      (error, stdout, stderr) => {
        if (!error || error.code === 1) {
          resolve(parseSnykJson(stdout));
          return;
        }

        const detail = stderr || stdout || error.message;
        reject(new Error(`Snyk no pudo completar el analisis: ${detail}`));
      }
    );
  });
}

function buildChildEnv(snykToken) {
  return {
    ...process.env,
    SNYK_TOKEN: snykToken
  };
}

function parseSnykJson(stdout) {
  try {
    return JSON.parse(stdout);
  } catch {
    throw new Error("Snyk no devolvio una respuesta JSON valida.");
  }
}

function normalizeSnykReport({ packageJson, dependencies, snykOutput }) {
  const results = Array.isArray(snykOutput) ? snykOutput : [snykOutput];
  const snykIssues = results.flatMap((result) => result.vulnerabilities || []);
  const vulnerabilities = snykIssues
    .filter((issue) => issue.type !== "license")
    .map((issue) => normalizeVulnerability(issue, packageJson, dependencies));
  const licenseIssues = snykIssues
    .filter((issue) => issue.type === "license")
    .map((issue) => normalizeLicenseIssue(issue, dependencies));

  return buildScaReport({
    packageJson,
    dependencies,
    vulnerabilities,
    licenseIssues,
    provider: {
      name: "Snyk CLI",
      mode: "snyk",
      realData: true,
      note: "Resultado generado por Snyk usando SNYK_TOKEN."
    }
  });
}

function normalizeVulnerability(issue, packageJson, dependencies) {
  const packageName = issue.packageName || issue.name || "paquete-desconocido";
  const dependency = dependencies.find((item) => item.name === packageName);
  const cves = issue.identifiers?.CVE || [];

  return {
    package: packageName,
    affected: readableAffectedRange(issue),
    severity: normalizeSeverity(issue.severity),
    cve: cves.length > 0 ? cves.join(", ") : issue.id || "SNYK",
    title: issue.title || "Vulnerabilidad detectada por Snyk",
    cvss: Number(issue.cvssScore || issue.cvss || 0),
    fixedVersion: readableFix(issue),
    impact: readableDescription(issue),
    recommendation: readableRecommendation(issue),
    currentVersion: issue.version || dependency?.version || "desconocida",
    declaredVersion: dependency?.version || issue.version || "desconocida",
    dependencyType: dependency?.type || "detectada",
    path: Array.isArray(issue.from)
      ? issue.from.join(" > ")
      : `${packageJson.name || "app"} > ${packageName}`
  };
}

function normalizeLicenseIssue(issue, dependencies) {
  const packageName = issue.packageName || issue.name || "paquete-desconocido";
  const dependency = dependencies.find((item) => item.name === packageName);

  return {
    package: packageName,
    currentVersion: issue.version || dependency?.version || "desconocida",
    dependencyType: dependency?.type || "detectada",
    license: issue.license || issue.id || "Licencia detectada por Snyk",
    health: "active",
    level: normalizeSeverity(issue.severity),
    title: issue.title || "Politica de licencia detectada por Snyk",
    recommendation:
      issue.description ||
      "Revisar la politica de licencia configurada en Snyk antes de distribuir el producto."
  };
}

function readableAffectedRange(issue) {
  if (Array.isArray(issue.semver?.vulnerable)) {
    return issue.semver.vulnerable.join(", ");
  }

  return issue.version ? `version detectada: ${issue.version}` : "Consultar Snyk";
}

function readableFix(issue) {
  if (Array.isArray(issue.fixedIn) && issue.fixedIn.length > 0) {
    return issue.fixedIn.join(", ");
  }

  const upgradeTarget = Array.isArray(issue.upgradePath)
    ? issue.upgradePath.filter(Boolean).at(-1)
    : null;

  return upgradeTarget || "Consultar recomendacion de Snyk";
}

function readableDescription(issue) {
  const source = issue.description || issue.title || "Snyk encontro un riesgo en esta dependencia.";
  return stripMarkup(source).slice(0, 320);
}

function readableRecommendation(issue) {
  if (Array.isArray(issue.fixedIn) && issue.fixedIn.length > 0) {
    return `Actualizar a una version corregida: ${issue.fixedIn.join(", ")}.`;
  }

  if (Array.isArray(issue.upgradePath) && issue.upgradePath.some(Boolean)) {
    return `Aplicar la ruta de actualizacion sugerida por Snyk: ${issue.upgradePath
      .filter(Boolean)
      .join(" > ")}.`;
  }

  return "Revisar el detalle en Snyk y aplicar la remediacion recomendada.";
}

function normalizeSeverity(severity) {
  return ["critical", "high", "medium", "low"].includes(severity)
    ? severity
    : "low";
}

function stripMarkup(value) {
  return String(value)
    .replace(/<[^>]*>/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}
