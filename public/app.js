const elements = {
  packageInput: document.querySelector("#packageInput"),
  loadDemoButton: document.querySelector("#loadDemoButton"),
  scanButton: document.querySelector("#scanButton"),
  clearButton: document.querySelector("#clearButton"),
  downloadButton: document.querySelector("#downloadButton"),
  fileInput: document.querySelector("#fileInput"),
  providerSelect: document.querySelector("#providerSelect"),
  providerBadge: document.querySelector("#providerBadge"),
  projectName: document.querySelector("#projectName"),
  dependencyCount: document.querySelector("#dependencyCount"),
  vulnerabilityCount: document.querySelector("#vulnerabilityCount"),
  licenseCount: document.querySelector("#licenseCount"),
  scoreRing: document.querySelector("#scoreRing"),
  scoreValue: document.querySelector("#scoreValue"),
  riskLevel: document.querySelector("#riskLevel"),
  reportProvider: document.querySelector("#reportProvider"),
  scoreText: document.querySelector("#scoreText"),
  severityRow: document.querySelector("#severityRow"),
  dependencyGraph: document.querySelector("#dependencyGraph"),
  vulnerabilityList: document.querySelector("#vulnerabilityList"),
  remediationList: document.querySelector("#remediationList"),
  licenseList: document.querySelector("#licenseList"),
  sbomTable: document.querySelector("#sbomTable"),
  toast: document.querySelector("#toast")
};

let latestReport = null;
let providerStatus = null;
let toastTimer = null;

const severityLabels = {
  critical: "Critico",
  high: "Alto",
  medium: "Medio",
  low: "Bajo"
};

const levelLabels = {
  critical: "Critico",
  high: "Alto",
  medium: "Medio",
  low: "Bajo",
  ok: "Correcto"
};

const riskLabels = {
  bajo: "Bajo",
  moderado: "Moderado",
  alto: "Alto",
  critico: "Critico"
};

const statusLabels = {
  abandoned: "Abandonado",
  active: "Activo",
  deprecated: "Deprecado",
  legacy: "Heredado",
  maintenance: "Mantenimiento",
  unknown: "Desconocido",
  vulnerable: "Vulnerable"
};

const riskMessages = {
  bajo: "El proyecto no muestra riesgos relevantes dentro de la base de demo.",
  moderado: "Hay riesgos atendibles. Conviene programar actualizaciones antes del siguiente release.",
  alto: "El proyecto tiene exposicion importante. Prioriza parches antes de desplegar.",
  critico: "El proyecto requiere remediacion inmediata antes de produccion."
};

elements.loadDemoButton.addEventListener("click", loadDemoPackage);
elements.scanButton.addEventListener("click", scanCurrentPackage);
elements.clearButton.addEventListener("click", clearEditor);
elements.downloadButton.addEventListener("click", downloadReport);
elements.fileInput.addEventListener("change", handleFileUpload);
elements.providerSelect.addEventListener("change", () => {
  updateProviderBadge();
  scanCurrentPackage();
});
window.addEventListener("resize", () => {
  if (latestReport) drawGraph(latestReport);
});

initialize();

async function initialize() {
  await loadProviderStatus();
  await loadDemoPackage();
}

async function loadProviderStatus() {
  try {
    const response = await fetch("/api/providers");
    providerStatus = await response.json();
    elements.providerSelect.value = "auto";
    updateProviderBadge();
  } catch {
    elements.providerBadge.textContent = "Proveedor no disponible";
    elements.providerBadge.className = "offline";
  }
}

async function loadDemoPackage() {
  try {
    const response = await fetch("/api/demo-package");
    const data = await response.json();
    elements.packageInput.value = JSON.stringify(data.packageJson, null, 2);
    await scanCurrentPackage();
    showToast("Proyecto de ejemplo cargado.");
  } catch (error) {
    showToast(error.message || "No se pudo cargar el ejemplo.");
  }
}

async function scanCurrentPackage() {
  const packageJson = elements.packageInput.value.trim();

  if (!packageJson) {
    showToast("Pega o sube un package.json para analizar.");
    return;
  }

  setBusy(true);

  try {
    const response = await fetch("/api/scan", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        packageJson,
        provider: elements.providerSelect.value
      })
    });
    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.error || "No se pudo analizar el proyecto.");
    }

    latestReport = data;
    renderReport(data);
    elements.downloadButton.disabled = false;
    showToast("Analisis SCA completado.");
  } catch (error) {
    showToast(error.message || "No se pudo analizar el proyecto.");
  } finally {
    setBusy(false);
  }
}

function renderReport(report) {
  const { summary, project } = report;
  elements.projectName.textContent = `${project.name} v${project.version}`;
  elements.dependencyCount.textContent = summary.totalDependencies;
  elements.vulnerabilityCount.textContent = summary.vulnerabilities;
  elements.licenseCount.textContent = summary.licenseIssues;
  elements.scoreValue.textContent = summary.score;
  elements.scoreRing.style.setProperty("--score-deg", `${summary.score * 3.6}deg`);
  elements.riskLevel.textContent = `Riesgo ${riskLabels[summary.riskLevel] || summary.riskLevel}`;
  elements.riskLevel.className = `status-pill ${summary.riskLevel}`;
  elements.reportProvider.textContent = `Proveedor: ${report.provider?.name || "No definido"}`;
  elements.scoreText.textContent = riskMessages[summary.riskLevel];

  renderSeverity(summary.severityCounts);
  renderVulnerabilities(report.vulnerabilities);
  renderRemediation(report.remediationPlan);
  renderLicenseIssues(report.licenseIssues);
  renderSbom(report.sbom);
  drawGraph(report);
}

function renderSeverity(counts = {}) {
  const severities = ["critical", "high", "medium", "low"];
  elements.severityRow.innerHTML = severities
    .map(
      (severity) =>
        `<span class="severity-pill ${severity}">${severityLabels[severity]}: ${
          counts[severity] || 0
        }</span>`
    )
    .join("");
}

function renderVulnerabilities(vulnerabilities) {
  if (vulnerabilities.length === 0) {
    elements.vulnerabilityList.innerHTML =
      '<div class="empty-state">No se encontraron vulnerabilidades con la base de conocimiento de esta demo.</div>';
    return;
  }

  elements.vulnerabilityList.innerHTML = vulnerabilities
    .map(
      (item) => `
        <section class="finding ${item.severity}">
          <div class="finding-header">
            <h3>${escapeHtml(item.package)} ${escapeHtml(item.currentVersion)}</h3>
            <span class="tag ${item.severity}">${severityLabels[item.severity]}</span>
          </div>
          <p><strong>${escapeHtml(item.cve)}</strong> - ${escapeHtml(item.title)}</p>
          <div class="finding-meta">
            <span>CVSS ${escapeHtml(String(item.cvss))}</span>
            <span>${escapeHtml(item.dependencyType)}</span>
            <span>${escapeHtml(item.path)}</span>
          </div>
          <p>${escapeHtml(item.impact)}</p>
          <p><strong>Remediacion:</strong> ${escapeHtml(item.recommendation)}</p>
        </section>
      `
    )
    .join("");
}

function renderRemediation(steps) {
  elements.remediationList.innerHTML = steps
    .map(
      (step) => `
        <section class="remediation">
          <div class="remediation-header">
            <h3>${escapeHtml(step.title)}</h3>
            <span class="tag">${escapeHtml(step.priority)}</span>
          </div>
          <p>${escapeHtml(step.detail)}</p>
        </section>
      `
    )
    .join("");
}

function renderLicenseIssues(issues) {
  if (issues.length === 0) {
    elements.licenseList.innerHTML =
      '<div class="empty-state">No hay alertas de licencia o mantenimiento en este paquete.</div>';
    return;
  }

  elements.licenseList.innerHTML = issues
    .map(
      (item) => `
        <section class="finding ${item.level}">
          <div class="finding-header">
            <h3>${escapeHtml(item.package)}</h3>
            <span class="tag ${item.level}">${escapeHtml(levelLabels[item.level] || item.level)}</span>
          </div>
          <p><strong>${escapeHtml(item.title)}</strong> - ${escapeHtml(item.license)} / ${escapeHtml(
            statusLabels[item.health] || item.health
          )}</p>
          <p>${escapeHtml(item.recommendation)}</p>
        </section>
      `
    )
    .join("");
}

function renderSbom(sbom) {
  elements.sbomTable.innerHTML = sbom
    .map(
      (item) => `
        <tr>
          <td>${escapeHtml(item.name)}</td>
          <td>${escapeHtml(item.version)}</td>
          <td>${escapeHtml(item.type)}</td>
          <td><span class="tag ${item.status === "vulnerable" ? "high" : ""}">${escapeHtml(
            statusLabels[item.status] || item.status
          )}</span></td>
        </tr>
      `
    )
    .join("");
}

function drawGraph(report) {
  const canvas = elements.dependencyGraph;
  const ctx = canvas.getContext("2d");
  const rect = canvas.getBoundingClientRect();
  const dpr = window.devicePixelRatio || 1;
  canvas.width = Math.max(1, Math.floor(rect.width * dpr));
  canvas.height = Math.max(1, Math.floor(rect.height * dpr));
  ctx.scale(dpr, dpr);
  ctx.clearRect(0, 0, rect.width, rect.height);

  const width = rect.width;
  const height = rect.height;
  const centerY = height / 2;
  const packageNodes = report.sbom.slice(0, 12);
  const vulnByPackage = new Map(
    report.vulnerabilities.map((item) => [item.package, item.severity])
  );

  ctx.fillStyle = "#fffdf8";
  ctx.fillRect(0, 0, width, height);
  drawProjectNode(ctx, 44, centerY - 42, 190, 84, report.project.name);

  const columns = width < 760 ? 2 : 3;
  const startX = width < 760 ? 275 : 310;
  const usableWidth = Math.max(260, width - startX - 38);
  const colWidth = usableWidth / columns;
  const rowGap = 72;
  const rows = Math.ceil(packageNodes.length / columns);
  const startY = Math.max(42, centerY - ((rows - 1) * rowGap) / 2);

  packageNodes.forEach((node, index) => {
    const col = index % columns;
    const row = Math.floor(index / columns);
    const x = startX + col * colWidth;
    const y = startY + row * rowGap;
    const status = vulnByPackage.get(node.name) || node.status;
    drawConnector(ctx, 234, centerY, x - 12, y + 18, status);
    drawPackageNode(ctx, x, y, Math.min(170, colWidth - 24), 42, node, status);
  });

  if (packageNodes.length === 0) {
    ctx.fillStyle = "#687386";
    ctx.font = "700 16px system-ui";
    ctx.fillText("Ejecuta un analisis para crear el mapa.", 280, centerY);
  }
}

function drawProjectNode(ctx, x, y, width, height, name) {
  roundedRect(ctx, x, y, width, height, 8);
  ctx.fillStyle = "#162033";
  ctx.fill();
  ctx.strokeStyle = "#0f766e";
  ctx.lineWidth = 3;
  ctx.stroke();

  ctx.fillStyle = "#80e0d4";
  ctx.font = "800 12px system-ui";
  ctx.fillText("PROYECTO", x + 16, y + 26);
  ctx.fillStyle = "#ffffff";
  ctx.font = "800 17px system-ui";
  ctx.fillText(truncate(name, 16), x + 16, y + 54);
}

function drawPackageNode(ctx, x, y, width, height, node, status) {
  const color = colorForStatus(status);
  roundedRect(ctx, x, y, width, height, 8);
  ctx.fillStyle = "#ffffff";
  ctx.fill();
  ctx.strokeStyle = color;
  ctx.lineWidth = 2.5;
  ctx.stroke();

  ctx.fillStyle = color;
  ctx.beginPath();
  ctx.arc(x + 17, y + height / 2, 5, 0, Math.PI * 2);
  ctx.fill();

  ctx.fillStyle = "#162033";
  ctx.font = "800 13px system-ui";
  ctx.fillText(truncate(node.name, 18), x + 30, y + 18);
  ctx.fillStyle = "#687386";
  ctx.font = "700 11px system-ui";
  ctx.fillText(`${node.version} / ${node.type}`, x + 30, y + 34);
}

function drawConnector(ctx, fromX, fromY, toX, toY, status) {
  ctx.strokeStyle = colorForStatus(status);
  ctx.globalAlpha = 0.34;
  ctx.lineWidth = 2;
  ctx.beginPath();
  ctx.moveTo(fromX, fromY);
  ctx.bezierCurveTo(fromX + 50, fromY, toX - 70, toY, toX, toY);
  ctx.stroke();
  ctx.globalAlpha = 1;
}

function roundedRect(ctx, x, y, width, height, radius) {
  ctx.beginPath();
  ctx.moveTo(x + radius, y);
  ctx.arcTo(x + width, y, x + width, y + height, radius);
  ctx.arcTo(x + width, y + height, x, y + height, radius);
  ctx.arcTo(x, y + height, x, y, radius);
  ctx.arcTo(x, y, x + width, y, radius);
  ctx.closePath();
}

function colorForStatus(status) {
  if (status === "critical") return "#3a1514";
  if (status === "high" || status === "vulnerable") return "#d94f45";
  if (status === "medium" || status === "deprecated") return "#c98208";
  if (status === "low" || status === "maintenance" || status === "legacy") return "#2f855a";
  return "#0f766e";
}

function handleFileUpload(event) {
  const [file] = event.target.files;
  if (!file) return;

  const reader = new FileReader();
  reader.addEventListener("load", async () => {
    elements.packageInput.value = String(reader.result);
    await scanCurrentPackage();
  });
  reader.addEventListener("error", () => showToast("No se pudo leer el archivo."));
  reader.readAsText(file);
}

function clearEditor() {
  elements.packageInput.value = "";
  latestReport = null;
  elements.downloadButton.disabled = true;
  elements.projectName.textContent = "Esperando analisis";
  elements.dependencyCount.textContent = "0";
  elements.vulnerabilityCount.textContent = "0";
  elements.licenseCount.textContent = "0";
  elements.scoreValue.textContent = "--";
  elements.scoreRing.style.setProperty("--score-deg", "0deg");
  elements.riskLevel.textContent = "Sin datos";
  elements.riskLevel.className = "status-pill";
  elements.reportProvider.textContent = "Sin proveedor";
  elements.scoreText.textContent =
    "Ejecuta un analisis para ver el nivel de exposicion del proyecto.";
  elements.severityRow.innerHTML = "";
  elements.vulnerabilityList.innerHTML = "";
  elements.remediationList.innerHTML = "";
  elements.licenseList.innerHTML = "";
  elements.sbomTable.innerHTML = "";
  drawGraph({ project: { name: "" }, sbom: [], vulnerabilities: [] });
  showToast("Editor limpio.");
}

function downloadReport() {
  if (!latestReport) return;

  const blob = new Blob([JSON.stringify(latestReport, null, 2)], {
    type: "application/json"
  });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `${latestReport.project.name}-sca-report.json`;
  document.body.append(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

function setBusy(isBusy) {
  elements.scanButton.disabled = isBusy;
  elements.scanButton.querySelector("span").textContent = isBusy
    ? "Analizando..."
    : "Analizar composicion";
}

function updateProviderBadge() {
  const provider = elements.providerSelect.value;
  const snykConfigured = Boolean(providerStatus?.providers?.snyk?.configured);

  if (provider === "snyk") {
    elements.providerBadge.textContent = snykConfigured
      ? "Snyk configurado"
      : "Falta SNYK_TOKEN";
    elements.providerBadge.className = snykConfigured ? "" : "offline";
    return;
  }

  if (provider === "auto") {
    elements.providerBadge.textContent = snykConfigured
      ? "Auto usara Snyk"
      : "Auto usara demo";
    elements.providerBadge.className = snykConfigured ? "" : "offline";
    return;
  }

  elements.providerBadge.textContent = "Modo demo";
  elements.providerBadge.className = "offline";
}

function showToast(message) {
  elements.toast.textContent = message;
  elements.toast.classList.add("visible");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => elements.toast.classList.remove("visible"), 2500);
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function truncate(value, maxLength) {
  const text = String(value || "");
  return text.length > maxLength ? `${text.slice(0, maxLength - 1)}...` : text;
}
