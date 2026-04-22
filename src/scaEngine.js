const vulnerabilityKnowledgeBase = [
  {
    package: "lodash",
    affected: "<4.17.21",
    severity: "high",
    cve: "CVE-2021-23337",
    title: "Prototype pollution en utilidades de objetos",
    cvss: 7.2,
    fixedVersion: "4.17.21",
    impact:
      "Un atacante podria modificar propiedades heredadas y alterar el comportamiento de la aplicacion.",
    recommendation:
      "Actualizar lodash a 4.17.21 o superior y ejecutar pruebas de regresion sobre funciones que mezclan objetos."
  },
  {
    package: "axios",
    affected: "<0.21.2",
    severity: "high",
    cve: "CVE-2021-3749",
    title: "Riesgo en solicitudes HTTP construidas con entradas no confiables",
    cvss: 7.5,
    fixedVersion: "0.21.2",
    impact:
      "La aplicacion podria enviar solicitudes no previstas si concatena URLs o parametros sin validacion.",
    recommendation:
      "Actualizar axios, validar dominios permitidos y evitar construir URLs directamente desde datos del usuario."
  },
  {
    package: "minimist",
    affected: "<1.2.6",
    severity: "critical",
    cve: "CVE-2021-44906",
    title: "Prototype pollution en parser de argumentos",
    cvss: 9.8,
    fixedVersion: "1.2.6",
    impact:
      "Una entrada manipulada puede contaminar objetos globales cuando el paquete procesa argumentos.",
    recommendation:
      "Actualizar minimist a 1.2.6 o superior. Si llega como dependencia transitiva, actualizar el paquete padre."
  },
  {
    package: "moment",
    affected: "<2.29.4",
    severity: "medium",
    cve: "CVE-2022-31129",
    title: "Consumo excesivo de recursos al parsear fechas",
    cvss: 5.3,
    fixedVersion: "2.29.4",
    impact:
      "Entradas maliciosas pueden provocar lentitud o denegacion de servicio en rutas que procesan fechas.",
    recommendation:
      "Actualizar moment y validar formatos de fecha antes de enviarlos al parser."
  },
  {
    package: "debug",
    affected: "<2.6.9",
    severity: "medium",
    cve: "CVE-2017-16137",
    title: "Expresion regular vulnerable a ReDoS",
    cvss: 5.9,
    fixedVersion: "2.6.9",
    impact:
      "Una cadena especialmente creada puede bloquear el event loop durante el procesamiento de logs.",
    recommendation:
      "Actualizar debug en dependencias directas y revisar paquetes que aun arrastran versiones antiguas."
  },
  {
    package: "qs",
    affected: "<6.5.3",
    severity: "high",
    cve: "CVE-2022-24999",
    title: "Prototype pollution al parsear query strings",
    cvss: 7.5,
    fixedVersion: "6.5.3",
    impact:
      "Parametros de URL manipulados pueden alterar objetos internos si se parsean sin controles.",
    recommendation:
      "Actualizar qs y limitar profundidad/tamano de parametros en endpoints publicos."
  },
  {
    package: "node-sass",
    affected: "<7.0.0",
    severity: "medium",
    cve: "SCA-DEMO-LEGACY-BINARY",
    title: "Binarios nativos antiguos y mantenimiento reducido",
    cvss: 4.6,
    fixedVersion: "migrar a sass",
    impact:
      "Dependencias nativas antiguas aumentan el costo de parcheo y pueden romper builds en ambientes nuevos.",
    recommendation:
      "Migrar a sass, que es la implementacion recomendada y evita binarios nativos obsoletos."
  }
];

const packageMetadata = {
  "@angular/core": { license: "MIT", health: "active" },
  axios: { license: "MIT", health: "active" },
  bootstrap: { license: "MIT", health: "active" },
  debug: { license: "MIT", health: "active" },
  express: { license: "MIT", health: "active" },
  jquery: { license: "MIT", health: "legacy" },
  "left-pad": { license: "WTFPL", health: "abandoned" },
  lodash: { license: "MIT", health: "active" },
  minimist: { license: "MIT", health: "active" },
  moment: { license: "MIT", health: "maintenance" },
  "node-sass": { license: "MIT", health: "deprecated" },
  qs: { license: "BSD-3-Clause", health: "active" },
  react: { license: "MIT", health: "active" },
  request: { license: "Apache-2.0", health: "deprecated" },
  vue: { license: "MIT", health: "active" }
};

const riskyLicenses = new Set(["GPL-3.0", "AGPL-3.0", "LGPL-3.0", "UNKNOWN"]);

const demoPackage = {
  name: "Prueba-SCA",
  version: "1.0.0",
  description: "Proyecto vulnerable usado para demostrar Software Composition Analysis",
  dependencies: {
    express: "4.16.0",
    lodash: "4.17.20",
    axios: "0.21.1",
    minimist: "0.0.8",
    moment: "2.18.1",
    qs: "6.4.0",
    react: "18.2.0",
    request: "2.88.0"
  },
  devDependencies: {
    debug: "2.6.8",
    "node-sass": "4.14.1"
  }
};

const severityWeight = {
  critical: 28,
  high: 18,
  medium: 10,
  low: 5
};

const localProvider = {
  name: "Motor demo local",
  mode: "demo",
  realData: false,
  note: "Usa una base local de ejemplo. Configura SNYK_TOKEN para usar Snyk."
};

export function getDemoPackage() {
  return demoPackage;
}

export function scanPackageJson(input, options = {}) {
  const packageJson = parsePackageJson(input);
  const dependencies = collectDependencies(packageJson);
  const vulnerabilities = dependencies.flatMap((dependency) =>
    vulnerabilityKnowledgeBase
      .filter(
        (item) =>
          item.package === dependency.name &&
          versionSatisfies(dependency.version, item.affected)
      )
      .map((item) => ({
        ...item,
        currentVersion: cleanVersion(dependency.version),
        declaredVersion: dependency.version,
        dependencyType: dependency.type,
        path: `${packageJson.name || "app"} > ${dependency.name}`
      }))
  );

  const licenseIssues = dependencies
    .map((dependency) => {
      const meta = packageMetadata[dependency.name] || {
        license: "UNKNOWN",
        health: "unknown"
      };
      const risk = getLicenseRisk(meta);

      if (risk.level === "ok") {
        return null;
      }

      return {
        package: dependency.name,
        currentVersion: cleanVersion(dependency.version),
        dependencyType: dependency.type,
        license: meta.license,
        health: meta.health,
        ...risk
      };
    })
    .filter(Boolean);

  return buildScaReport({
    packageJson,
    dependencies,
    vulnerabilities,
    licenseIssues,
    provider: options.provider || localProvider
  });
}

export function buildScaReport({
  packageJson,
  dependencies = collectDependencies(packageJson),
  vulnerabilities = [],
  licenseIssues = [],
  provider = localProvider
}) {
  const severityCounts = countBy(vulnerabilities, "severity");
  const score = calculateScore(vulnerabilities, licenseIssues, dependencies);
  const dependencyGroups = countBy(dependencies, "type");

  return {
    project: {
      name: packageJson.name || "proyecto-sin-nombre",
      version: packageJson.version || "0.0.0",
      description: packageJson.description || "Sin descripcion"
    },
    provider,
    generatedAt: new Date().toISOString(),
    summary: {
      totalDependencies: dependencies.length,
      vulnerabilities: vulnerabilities.length,
      licenseIssues: licenseIssues.length,
      score,
      riskLevel: getRiskLevel(score),
      severityCounts,
      dependencyGroups
    },
    vulnerabilities: vulnerabilities.sort(sortBySeverity),
    licenseIssues,
    sbom: dependencies.map((dependency) => {
      const meta = packageMetadata[dependency.name] || {
        license: "UNKNOWN",
        health: "unknown"
      };
      const vulnCount = vulnerabilities.filter(
        (vulnerability) => vulnerability.package === dependency.name
      ).length;

      return {
        name: dependency.name,
        version: cleanVersion(dependency.version),
        declaredVersion: dependency.version,
        type: dependency.type,
        license: meta.license,
        health: meta.health,
        status: vulnCount > 0 ? "vulnerable" : meta.health
      };
    }),
    remediationPlan: buildRemediationPlan(vulnerabilities, licenseIssues)
  };
}

export function parsePackageJson(input) {
  if (!input) {
    throw new Error("Debes enviar el contenido de un package.json.");
  }

  if (typeof input === "string") {
    try {
      return JSON.parse(input);
    } catch {
      throw new Error("El package.json no es JSON valido.");
    }
  }

  if (typeof input === "object") {
    return input;
  }

  throw new Error("Formato no soportado para analizar.");
}

export function collectDependencies(packageJson) {
  const sections = [
    ["dependencies", "produccion"],
    ["devDependencies", "desarrollo"],
    ["optionalDependencies", "opcional"],
    ["peerDependencies", "peer"]
  ];

  return sections.flatMap(([section, type]) =>
    Object.entries(packageJson[section] || {}).map(([name, version]) => ({
      name,
      version: String(version),
      type
    }))
  );
}

function getLicenseRisk(meta) {
  if (riskyLicenses.has(meta.license)) {
    return {
      level: "high",
      title: "Licencia restrictiva o desconocida",
      recommendation:
        "Revisar con el equipo legal antes de distribuir el producto."
    };
  }

  if (meta.health === "deprecated") {
    return {
      level: "medium",
      title: "Paquete deprecado",
      recommendation: "Planificar migracion a una alternativa mantenida."
    };
  }

  if (meta.health === "abandoned") {
    return {
      level: "high",
      title: "Paquete abandonado",
      recommendation:
        "Eliminarlo o reemplazarlo por una libreria con mantenimiento activo."
    };
  }

  if (meta.health === "maintenance") {
    return {
      level: "low",
      title: "Modo mantenimiento",
      recommendation:
        "Mantenerlo actualizado y evaluar alternativas si el uso crece."
    };
  }

  if (meta.health === "legacy") {
    return {
      level: "low",
      title: "Dependencia heredada",
      recommendation:
        "Revisar si sigue siendo necesaria o si puede reemplazarse por APIs modernas."
    };
  }

  return { level: "ok" };
}

function buildRemediationPlan(vulnerabilities, licenseIssues) {
  const criticalAndHigh = vulnerabilities.filter((item) =>
    ["critical", "high"].includes(item.severity)
  );
  const mediumAndLow = vulnerabilities.filter(
    (item) => !["critical", "high"].includes(item.severity)
  );

  const steps = [];

  if (criticalAndHigh.length > 0) {
    steps.push({
      priority: "P1",
      title: "Parchear vulnerabilidades criticas y altas",
      detail: criticalAndHigh
        .map(
          (item) =>
            `${item.package}: ${item.currentVersion} -> ${item.fixedVersion}`
        )
        .join(", ")
    });
  }

  if (mediumAndLow.length > 0) {
    steps.push({
      priority: "P2",
      title: "Actualizar dependencias con riesgo moderado",
      detail: mediumAndLow
        .map(
          (item) =>
            `${item.package}: ${item.currentVersion} -> ${item.fixedVersion}`
        )
        .join(", ")
    });
  }

  if (licenseIssues.length > 0) {
    steps.push({
      priority: "P3",
      title: "Resolver alertas de licencia y mantenimiento",
      detail: licenseIssues
        .map((item) => `${item.package}: ${item.title.toLowerCase()}`)
        .join(", ")
    });
  }

  if (steps.length === 0) {
    steps.push({
      priority: "OK",
      title: "No se encontraron riesgos en la base de demo",
      detail:
        "Mantener actualizaciones automatizadas y repetir el escaneo en cada pull request."
    });
  }

  return steps;
}

function calculateScore(vulnerabilities, licenseIssues, dependencies) {
  const vulnerabilityPenalty = vulnerabilities.reduce(
    (total, item) => total + severityWeight[item.severity],
    0
  );
  const licensePenalty = licenseIssues.reduce(
    (total, item) => total + (item.level === "high" ? 12 : item.level === "medium" ? 8 : 4),
    0
  );
  const inventoryPenalty = dependencies.length > 12 ? 5 : 0;

  return Math.max(0, Math.min(100, 100 - vulnerabilityPenalty - licensePenalty - inventoryPenalty));
}

function getRiskLevel(score) {
  if (score >= 85) return "bajo";
  if (score >= 65) return "moderado";
  if (score >= 40) return "alto";
  return "critico";
}

function countBy(items, property) {
  return items.reduce((counts, item) => {
    const key = item[property] || "sin-clasificar";
    counts[key] = (counts[key] || 0) + 1;
    return counts;
  }, {});
}

function sortBySeverity(a, b) {
  const order = { critical: 0, high: 1, medium: 2, low: 3 };
  return (order[a.severity] ?? 9) - (order[b.severity] ?? 9);
}

function versionSatisfies(version, range) {
  const normalized = cleanVersion(version);

  if (range.startsWith("<=")) {
    return compareVersions(normalized, range.slice(2)) <= 0;
  }

  if (range.startsWith("<")) {
    return compareVersions(normalized, range.slice(1)) < 0;
  }

  if (range.startsWith(">=")) {
    return compareVersions(normalized, range.slice(2)) >= 0;
  }

  if (range.startsWith(">")) {
    return compareVersions(normalized, range.slice(1)) > 0;
  }

  return normalized === cleanVersion(range);
}

function compareVersions(left, right) {
  const a = cleanVersion(left).split(".").map(toNumber);
  const b = cleanVersion(right).split(".").map(toNumber);
  const length = Math.max(a.length, b.length);

  for (let index = 0; index < length; index += 1) {
    const diff = (a[index] || 0) - (b[index] || 0);
    if (diff !== 0) return diff > 0 ? 1 : -1;
  }

  return 0;
}

function cleanVersion(version) {
  return String(version)
    .trim()
    .replace(/^[~^<>=\s]+/, "")
    .replace(/^v/i, "")
    .split(" ")[0]
    .split("-")[0]
    .replace(/[^\d.]/g, "") || "0.0.0";
}

function toNumber(value) {
  const parsed = Number.parseInt(value, 10);
  return Number.isFinite(parsed) ? parsed : 0;
}
