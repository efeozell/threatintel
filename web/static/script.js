// Global değişken — mevcut analiz sonucunu saklar
let currentResult = null;

// Analyze with Enter
document.addEventListener("DOMContentLoaded", function () {
    document.getElementById("targetInput").addEventListener("keypress", function (e) {
        if (e.key === "Enter") analyze();
    });
});

function setExample(value) {
    document.getElementById("targetInput").value = value;
    analyze();
}

function showLoading() {
    document.getElementById("loadingSection").classList.remove("d-none");
    document.getElementById("resultsSection").classList.add("d-none");
    document.getElementById("errorSection").classList.add("d-none");
}

function hideLoading() {
    document.getElementById("loadingSection").classList.add("d-none");
}

function showError(message) {
    hideLoading();
    document.getElementById("errorMessage").textContent = message;
    document.getElementById("errorSection").classList.remove("d-none");
    document.getElementById("resultsSection").classList.add("d-none");
}

function getScoreClass(score) {
    if (score <= 30) return "clean";
    if (score <= 60) return "suspicious";
    if (score <= 80) return "high-risk";
    return "dangerous";
}

function getScoreEmoji(level) {
    const emojis = {
        "CLEAR": "🟢",
        "SUSPICIOUS": "🟡",
        "HIGH RISK": "🟠",
        "DANGEROUS": "🔴"
    };
    return emojis[level] || "⚪";
}

function renderScore(data) {
    const score = data.final_score;
    const level = data.threat_level.level;
    const scoreClass = getScoreClass(score);

    // Score card
    const scoreCard = document.getElementById("scoreCard");
    scoreCard.className = `card border-0 score-${scoreClass}`;

    document.getElementById("scoreValue").textContent = score;
    document.getElementById("scoreValue").className = `display-1 fw-bold score-${scoreClass}`;

    document.getElementById("threatLevel").textContent =
        `${getScoreEmoji(level)} ${level}`;
    document.getElementById("threatLevel").className =
        `fs-4 fw-bold mt-1 score-${scoreClass}`;

    document.getElementById("targetInfo").textContent =
        `${data.target} · ${data.target_type.toUpperCase()}`;

    // Progress bar
    const bar = document.getElementById("scoreBar");
    bar.style.width = `${score}%`;
    bar.className = `progress-bar bar-${scoreClass}`;
}

function infoRow(label, value, valueClass = "") {
    return `
        <div class="info-row">
            <span class="info-label">${label}</span>
            <span class="${valueClass}">${value ?? "N/A"}</span>
        </div>
    `;
}

function renderVirusTotal(vt) {
    const card = document.getElementById("vtCard");

    if (!vt || vt.error) {
        card.innerHTML = `<p class="text-danger">❌ ${vt?.error || "Error"}</p>`;
        return;
    }
    if (vt.skipped) {
        card.innerHTML = `<p class="text-muted">⏭ ${vt.reason}</p>`;
        return;
    }

    const stats = vt.stats || {};
    const malicious = stats.malicious || 0;
    const total = stats.total_engines || 0;
    const malClass = malicious > 0 ? "text-danger" : "text-success";

    let html = `
        ${infoRow("Malicious", `${malicious}/${total}`, malClass)}
        ${infoRow("Suspicious", `${stats.suspicious || 0}/${total}`)}
        ${infoRow("Harmless", `${stats.harmless || 0}/${total}`, "text-success")}
    `;

    if (vt.target_type === "ip") {
        html += infoRow("Country", vt.country);
        html += infoRow("Owner", vt.owner);
        html += infoRow("ASN", vt.asn);
    }
    if (vt.target_type === "domain") {
        html += infoRow("Registrar", vt.registrar);
    }
    if (vt.target_type === "hash") {
        html += infoRow("File Name", vt.file_name);
        html += infoRow("File Type", vt.file_type);
        html += infoRow("Size", vt.file_size ? `${vt.file_size.toLocaleString()} bytes` : "N/A");
    }

    card.innerHTML = html;
}

function renderAbuseIPDB(abuse) {
    const card = document.getElementById("abuseCard");

    if (!abuse || abuse.error) {
        card.innerHTML = `<p class="text-danger">❌ ${abuse?.error || "Error"}</p>`;
        return;
    }
    if (abuse.skipped) {
        card.innerHTML = `<p class="text-muted">⏭ ${abuse.reason}</p>`;
        return;
    }

    const score = abuse.abuse_score || 0;
    const scoreClass = score > 50 ? "text-danger" : score > 20 ? "text-warning" : "text-success";
    const torText = abuse.is_tor ?
        '<span class="text-danger">✓ Tor Node</span>' :
        '<span class="text-success">✗ Not Tor</span>';

    card.innerHTML = `
        ${infoRow("Abuse Score", `${score}/100`, scoreClass)}
        ${infoRow("Reports", abuse.total_reports?.toLocaleString())}
        ${infoRow("Country", abuse.country)}
        ${infoRow("ISP", abuse.isp)}
        ${infoRow("Usage Type", abuse.usage_type)}
        ${infoRow("Tor Node", torText)}
    `;
}

function renderShodan(shodan) {
    const card = document.getElementById("shodanCard");

    if (!shodan || shodan.error) {
        card.innerHTML = `<p class="text-danger">❌ ${shodan?.error || "Error"}</p>`;
        return;
    }
    if (shodan.skipped) {
        card.innerHTML = `<p class="text-muted">⏭ ${shodan.reason}</p>`;
        return;
    }
    if (!shodan.found) {
        card.innerHTML = `<p class="text-muted">Not indexed in Shodan</p>`;
        return;
    }

    const ports = (shodan.open_ports || []).join(", ") || "None";
    const vulns = (shodan.vulns || []).join(", ") || "None";
    const vulnClass = shodan.vulns?.length > 0 ? "text-danger" : "text-success";
    const critClass = shodan.critical_ports?.length > 0 ? "text-warning" : "text-success";
    const critPorts = (shodan.critical_ports || []).join(", ") || "None";

    card.innerHTML = `
        ${infoRow("Organisation", shodan.org)}
        ${infoRow("Country", shodan.country)}
        ${infoRow("City", shodan.city)}
        ${infoRow("Open Ports", ports)}
        ${infoRow("Critical Ports", critPorts, critClass)}
        ${infoRow("CVEs: ", vulns, vulnClass)}
    `;
}

function renderFindings(findings) {
    const card = document.getElementById("findingsCard");

    if (!findings || findings.length === 0) {
        card.innerHTML = `<p class="text-muted">No threat indicators found</p>`;
        return;
    }

    card.innerHTML = findings
        .map(f => `<div class="finding-item">• ${f}</div>`)
        .join("");
}

async function openVTDetails() {
    if (!currentResult) return;

    const target = currentResult.target;
    const target_type = currentResult.target_type;

    // Modalı aç
    const modal = new bootstrap.Modal(document.getElementById("vtModal"));
    modal.show();

    // Detections tab'ı doldur
    renderDetections(currentResult.raw.virustotal);

    // Relations tab'ı doldur — API'den al
    document.getElementById("relationsContent").innerHTML = `
        <div class="text-center text-muted py-3">
            <div class="spinner-border spinner-border-sm"></div>
            Loading relations...
        </div>
    `;

    try {
        const response = await fetch("/api/vt-details", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ target, target_type })
        });
        const result = await response.json();

        if (result.success) {
            renderRelations(result.relations, target_type);
        } else {
            document.getElementById("relationsContent").innerHTML =
                `<p class="text-danger">❌ ${result.error}</p>`;
        }
    } catch (e) {
        document.getElementById("relationsContent").innerHTML =
            `<p class="text-danger">❌ Connection error</p>`;
    }
}

function renderDetections(vt) {
    const container = document.getElementById("detectionsContent");

    if (!vt || vt.error || vt.skipped) {
        container.innerHTML = `<p class="text-muted">No detection data available</p>`;
        return;
    }

    const detections = vt.detections || [];
    const total = vt.total_engines || vt.stats?.total_engines || 0;
    const malicious = detections.filter(d => d.category === "malicious").length;
    const suspicious = detections.filter(d => d.category === "suspicious").length;

    if (detections.length === 0) {
        container.innerHTML = `
            <div class="alert alert-success vt-alert-clean">
                <i class="bi bi-check-circle"></i>
                No engines flagged this as malicious (${total} engines scanned)
            </div>
        `;
        return;
    }

    let html = `
        <div class="mb-3 d-flex align-items-center gap-2">
            <span class="badge vt-badge-mal">${malicious} Malicious</span>
            <span class="badge vt-badge-sus">${suspicious} Suspicious</span>
            <span class="text-muted small">out of ${total} engines</span>
        </div>
        <div class="table-responsive vt-table-wrap">
            <table class="table table-dark table-sm table-hover vt-table">
                <thead>
                    <tr>
                        <th>Engine</th>
                        <th>Category</th>
                        <th>Detection</th>
                    </tr>
                </thead>
                <tbody>
    `;

    detections.forEach(d => {
        const badgeClass = d.category === "malicious" ? "vt-badge-mal" : "vt-badge-sus";
        html += `
            <tr>
                <td>${d.engine}</td>
                <td><span class="badge ${badgeClass}">${d.category}</span></td>
                <td class="text-muted small">${d.result || "—"}</td>
            </tr>
        `;
    });

    html += `</tbody></table></div>`;
    container.innerHTML = html;
}

function renderRelations(relations, target_type) {
    const container = document.getElementById("relationsContent");

    if (target_type === "ip") {
        const urls = relations.related_urls || [];

        if (urls.length === 0) {
            container.innerHTML = `<p class="text-muted">No related URLs found</p>`;
            return;
        }

        let html = `
            <p class="text-muted small mb-2">URLs observed on this IP:</p>
            <div class="table-responsive vt-table-wrap">
                <table class="table table-dark table-sm table-hover vt-table">
                    <thead>
                        <tr>
                            <th>URL</th>
                            <th>Malicious</th>
                        </tr>
                    </thead>
                    <tbody>
        `;

        urls.forEach(u => {
            const malClass = u.malicious > 0 ? "text-danger" : "text-success";
            html += `
                <tr>
                    <td class="small text-break">${u.url}</td>
                    <td class="${malClass}">${u.malicious}</td>
                </tr>
            `;
        });

        html += `</tbody></table></div>`;
        container.innerHTML = html;

    } else if (target_type === "domain") {
        const ips = relations.related_ips || [];

        if (ips.length === 0) {
            container.innerHTML = `<p class="text-muted">No related IPs found</p>`;
            return;
        }

        let html = `
            <p class="text-muted small mb-2">IP resolutions for this domain:</p>
            <div class="table-responsive vt-table-wrap">
                <table class="table table-dark table-sm table-hover vt-table">
                    <thead>
                        <tr><th>IP Address</th><th>Last Resolved</th></tr>
                    </thead>
                    <tbody>
        `;

        ips.forEach(ip => {
            html += `
                <tr>
                    <td>${ip.ip}</td>
                    <td class="text-muted small">${ip.last_resolved || "—"}</td>
                </tr>
            `;
        });

        html += `</tbody></table></div>`;
        container.innerHTML = html;

    } else {
        container.innerHTML = `<p class="text-muted">Relations not available for hash queries</p>`;
    }
}

function openAbuseDetails() {
    if (!currentResult) return;

    const abuse = currentResult.raw.abuseipdb;
    const modal = new bootstrap.Modal(document.getElementById("abuseModal"));
    modal.show();

    renderReports(abuse);
    renderCategories(abuse);
}

function renderReports(abuse) {
    const container = document.getElementById("reportsContent");

    if (!abuse || abuse.skipped || abuse.error) {
        container.innerHTML = `<p class="text-muted">No report data available</p>`;
        return;
    }

    const reports = abuse.recent_reports || [];

    if (reports.length === 0) {
        container.innerHTML = `
            <div class="alert alert-success abuse-alert-clean">
                <i class="bi bi-check-circle"></i>
                No recent reports found
            </div>
        `;
        return;
    }

    let html = `
        <p class="text-muted small mb-2">Last ${reports.length} reports:</p>
        <div class="table-responsive abuse-table-wrap">
            <table class="table table-dark table-sm table-hover abuse-table">
                <thead>
                    <tr>
                        <th>Date</th>
                        <th>Country</th>
                        <th>Categories</th>
                        <th>Comment</th>
                    </tr>
                </thead>
                <tbody>
    `;

    reports.forEach(r => {
        const date = r.reported_at ? r.reported_at.split("T")[0] : "—";
        const cats = (r.categories || [])
            .map(c => `<span class="badge abuse-badge-cat me-1">${c}</span>`)
            .join("");
        const comment = r.comment || "—";

        html += `
            <tr>
                <td class="text-muted small">${date}</td>
                <td>${r.country || "—"}</td>
                <td>${cats || "—"}</td>
                <td class="text-muted small">${comment}</td>
            </tr>
        `;
    });

    html += `</tbody></table></div>`;
    container.innerHTML = html;
}

function renderCategories(abuse) {
    const container = document.getElementById("categoriesContent");

    if (!abuse || abuse.skipped || abuse.error) {
        container.innerHTML = `<p class="text-muted">No category data available</p>`;
        return;
    }

    const cats = abuse.categories_count || {};
    const entries = Object.entries(cats).sort((a, b) => b[1] - a[1]);

    if (entries.length === 0) {
        container.innerHTML = `<p class="text-muted">No categories found</p>`;
        return;
    }

    const maxCount = entries[0][1];

    let html = `<p class="text-muted small mb-3">Attack categories reported for this IP:</p>`;

    entries.forEach(([cat, count]) => {
        const pct = Math.round((count / maxCount) * 100);
        html += `
            <div class="mb-2">
                <div class="d-flex justify-content-between mb-1">
                    <span class="small">${cat}</span>
                    <span class="small text-muted">${count} reports</span>
                </div>
                <div class="progress abuse-progress" style="height: 6px;">
                    <div class="progress-bar abuse-bar" style="width: ${pct}%"></div>
                </div>
            </div>
        `;
    });

    container.innerHTML = html;
}

function openShodanDetails() {
    if (!currentResult) return;

    const shodan = currentResult.raw.shodan;
    const modal = new bootstrap.Modal(document.getElementById("shodanModal"));
    modal.show();

    renderServices(shodan);
    renderVulns(shodan);
}

function renderServices(shodan) {
    const container = document.getElementById("servicesContent");

    if (!shodan || shodan.skipped || shodan.error || !shodan.found) {
        container.innerHTML = `<p class="text-muted">No service data available</p>`;
        return;
    }

    const services = shodan.all_services || shodan.services || [];

    if (services.length === 0) {
        container.innerHTML = `<p class="text-muted">No services found</p>`;
        return;
    }

    let html = `
        <div class="table-responsive shodan-table-wrap">
            <table class="table table-dark table-sm table-hover shodan-table">
                <thead>
                    <tr>
                        <th>Port</th>
                        <th>Protocol</th>
                        <th>Product</th>
                        <th>Version</th>
                        <th>Banner</th>
                    </tr>
                </thead>
                <tbody>
    `;

    services.forEach(s => {
        const criticalPorts = [21, 22, 23, 25, 445, 1433, 3306, 3389, 5900];
        const portClass = criticalPorts.includes(s.port) ? "shodan-port-critical" : "shodan-port-normal";
        const banner = s.banner ? s.banner.trim().split("\n")[0] : "—";

        html += `
            <tr>
                <td class="${portClass}">${s.port}</td>
                <td class="text-muted">${s.transport || "tcp"}</td>
                <td>${s.product || "—"}</td>
                <td class="text-muted small">${s.version || "—"}</td>
                <td class="text-muted small text-truncate" style="max-width:200px">${banner}</td>
            </tr>
        `;
    });

    html += `</tbody></table></div>`;
    container.innerHTML = html;
}

function renderVulns(shodan) {
    const container = document.getElementById("vulnsContent");

    if (!shodan || shodan.skipped || shodan.error || !shodan.found) {
        container.innerHTML = `<p class="text-muted">No vulnerability data available</p>`;
        return;
    }

    const vulns = shodan.vulns || [];

    if (vulns.length === 0) {
        container.innerHTML = `
            <div class="alert alert-success shodan-alert-clean">
                <i class="bi bi-check-circle"></i>
                No known vulnerabilities found
            </div>
        `;
        return;
    }

    let html = `
        <div class="alert alert-danger shodan-alert-danger mb-3">
            <i class="bi bi-exclamation-triangle"></i>
            <strong>${vulns.length} vulnerability(s) detected</strong>
        </div>
        <div class="list-group">
    `;

    vulns.forEach(cve => {
        html += `
            <div class="list-group-item shodan-vuln-item mb-2">
                <div class="d-flex justify-content-between align-items-center">
                    <span class="shodan-vuln-cve">
                        <i class="bi bi-bug"></i> ${cve}
                    </span>
                    <a href="https://nvd.nist.gov/vuln/detail/${cve}"
                       target="_blank"
                       class="btn btn-sm shodan-nvd-link">
                        NVD <i class="bi bi-box-arrow-up-right"></i>
                    </a>
                </div>
            </div>
        `;
    });

    html += `</div>`;
    container.innerHTML = html;
}

async function analyze() {
    const target = document.getElementById("targetInput").value.trim();

    if (!target) {
        showError("Please enter an IP address, domain, or hash");
        return;
    }

    // Disable the button
    const btn = document.getElementById("analyzeBtn");
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner-border spinner-border-sm"></span> Analyzing...';

    showLoading();

    try {
        const response = await fetch("/api/analyze", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ target })
        });

        const result = await response.json();

        if (!result.success) {
            showError(result.error || "An error occurred");
            return;
        }

        const data = result.data;
        currentResult = data;

        // Render the results
        hideLoading();
        document.getElementById("resultsSection").classList.remove("d-none");
        document.getElementById("errorSection").classList.add("d-none");

        renderScore(data);
        renderVirusTotal(data.raw.virustotal);
        renderAbuseIPDB(data.raw.abuseipdb);
        renderShodan(data.raw.shodan);
        renderFindings(data.findings);

        // IP ise Shodan butonu göster
        if (data.target_type === "ip" && data.raw.shodan &&
            !data.raw.shodan.skipped && data.raw.shodan.found) {
            document.getElementById("shodanDetailsBtn").style.display = "flex";
        } else {
            document.getElementById("shodanDetailsBtn").style.display = "none";
        }

    } catch (error) {
        showError("Connection error: " + error.message);
    } finally {
        btn.disabled = false;
        btn.innerHTML = '<i class="bi bi-search"></i> Analyze';
    }
}
