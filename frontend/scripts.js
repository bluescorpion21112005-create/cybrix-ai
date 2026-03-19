const API_BASE_URL = "http://127.0.0.1:8000/api/v1";

document.addEventListener("DOMContentLoaded", () => {
    setupEventListeners();
    loadRecentScans();
    loadVulnerabilityTypes();
    setInterval(loadRecentScans, 30000);
});

function setupEventListeners() {
    const mobileBtn = document.querySelector(".mobile-menu-btn");
    if (mobileBtn) {
        mobileBtn.addEventListener("click", toggleMobileMenu);
    }

    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener("click", function (e) {
            e.preventDefault();
            const target = document.querySelector(this.getAttribute("href"));
            if (target) {
                target.scrollIntoView({ behavior: "smooth" });
            }
        });
    });
}

function toggleMobileMenu() {
    console.log("Mobile menu toggled");
}

async function startScan() {
    const urlInput = document.getElementById("targetUrl");
    const scanTypeInput = document.getElementById("scanType");

    const url = urlInput ? urlInput.value.trim() : "";
    const scanType = scanTypeInput ? scanTypeInput.value : "full";

    if (!url) {
        showNotification("Iltimos, URL manzilini kiriting", "error");
        return;
    }

    try {
        new URL(url);
    } catch {
        showNotification("Noto'g'ri URL format", "error");
        return;
    }

    openScanModal();

    try {
        const response = await fetch(`${API_BASE_URL}/scan`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({
                url: url,
                scan_type: scanType
            })
        });

        const data = await response.json().catch(() => ({}));

        if (!response.ok) {
            showNotification(data.detail || data.message || "Skanerlashni boshlashda xatolik", "error");
            closeScanModal();
            return;
        }

        const scanId = data.scan_id || data.id;
        if (!scanId) {
            showNotification("Backend scan_id qaytarmadi", "error");
            closeScanModal();
            return;
        }

        showNotification("Skanerlash boshlandi", "success");
        updateProgressBar(20);
        pollScanStatus(scanId);
    } catch (error) {
        console.error("Scan error:", error);
        showNotification("Serverga ulanishda xatolik", "error");
        closeScanModal();
    }
}

function pollScanStatus(scanId) {
    let attempts = 0;
    const maxAttempts = 90;

    const interval = setInterval(async () => {
        attempts++;

        try {
            const response = await fetch(`${API_BASE_URL}/scan/${scanId}`);
            const data = await response.json().catch(() => ({}));

            if (!response.ok) {
                clearInterval(interval);
                showNotification(data.detail || "Skan holatini olishda xatolik", "error");
                closeScanModal();
                return;
            }

            if (data.status === "completed") {
                clearInterval(interval);
                updateProgressBar(100);
                await loadScanResults(scanId);
                showNotification("Skanerlash tugadi", "success");
            } else if (data.status === "failed") {
                clearInterval(interval);
                showNotification("Skanerlashda xatolik", "error");
                closeScanModal();
            } else {
                const progress = Math.min(20 + attempts * 2, 95);
                updateProgressBar(progress);
            }

            if (attempts >= maxAttempts) {
                clearInterval(interval);
                showNotification("Skanerlash juda uzoq davom etdi", "error");
                closeScanModal();
            }
        } catch (error) {
            clearInterval(interval);
            console.error("Poll error:", error);
            showNotification("Skan holatini kuzatishda xatolik", "error");
            closeScanModal();
        }
    }, 2000);
}

async function loadScanResults(scanId) {
    try {
        const response = await fetch(`${API_BASE_URL}/scan/${scanId}`);
        const data = await response.json().catch(() => ({}));

        if (!response.ok) {
            showNotification(data.detail || "Natijalarni yuklashda xatolik", "error");
            return;
        }

        displayScanResults(data);
        loadRecentScans();
    } catch (error) {
        console.error("Load results error:", error);
        showNotification("Natijalarni yuklashda xatolik", "error");
    }
}

function displayScanResults(data) {
    const resultsDiv = document.getElementById("resultsContent");
    if (!resultsDiv) return;

    const vulnerabilities = data.vulnerabilities || [];
    const summary = data.summary || {};
    const severityCounts = summary.severity_counts || {};

    let html = `
        <div class="summary-stats">
            <div class="summary-card ${getSeverityClass("critical")}">
                <div class="summary-value">${severityCounts.critical || 0}</div>
                <div class="summary-label">Critical</div>
            </div>
            <div class="summary-card ${getSeverityClass("high")}">
                <div class="summary-value">${severityCounts.high || 0}</div>
                <div class="summary-label">High</div>
            </div>
            <div class="summary-card ${getSeverityClass("medium")}">
                <div class="summary-value">${severityCounts.medium || 0}</div>
                <div class="summary-label">Medium</div>
            </div>
            <div class="summary-card ${getSeverityClass("low")}">
                <div class="summary-value">${severityCounts.low || 0}</div>
                <div class="summary-label">Low</div>
            </div>
        </div>
    `;

    if (vulnerabilities.length === 0) {
        html += `<p class="no-vulns">Hech qanday zaiflik topilmadi ✅</p>`;
    } else {
        html += `<h3>Aniqlangan zaifliklar:</h3>`;

        vulnerabilities.forEach((vuln, index) => {
            const severity = (vuln.severity || "info").toLowerCase();

            html += `
                <div class="vulnerability-item">
                    <div class="vuln-header ${severity}" onclick="toggleVuln(${index})">
                        <span class="vuln-title">${escapeHtml(vuln.type || "Noma'lum")}</span>
                        <span class="vuln-severity" style="background: ${getSeverityColor(severity)}">
                            ${severity.toUpperCase()}
                        </span>
                    </div>
                    <div class="vuln-content" id="vuln-${index}">
                        <p class="vuln-description">${escapeHtml(vuln.description || "")}</p>

                        ${vuln.remediation ? `
                            <div class="vuln-remediation">
                                <h4>🔧 Remediation</h4>
                                <p>${escapeHtml(vuln.remediation)}</p>
                            </div>
                        ` : ""}

                        ${vuln.ai_analysis ? `
                            <div class="ai-analysis">
                                <h4>🤖 AI tahlili</h4>
                                <p><strong>Impact score:</strong> ${escapeHtml(String(vuln.ai_analysis.impact_score ?? "N/A"))}</p>
                                <p><strong>Exploit difficulty:</strong> ${escapeHtml(String(vuln.ai_analysis.exploit_difficulty ?? "N/A"))}</p>
                                <p><strong>Priority:</strong> ${escapeHtml(String(vuln.ai_analysis.priority ?? "N/A"))}</p>
                            </div>
                        ` : ""}
                    </div>
                </div>
            `;
        });
    }

    const reportId = data.id || data.scan_id;

    if (reportId) {
        html += `
            <div style="margin-top: 2rem; display: flex; gap: 1rem; justify-content: center; flex-wrap: wrap;">
                <button class="btn btn-outline" onclick="downloadReport('${reportId}', 'html')">
                    <i class="fas fa-file-code"></i> HTML
                </button>
                <button class="btn btn-outline" onclick="downloadReport('${reportId}', 'pdf')">
                    <i class="fas fa-file-pdf"></i> PDF
                </button>
                <button class="btn btn-outline" onclick="downloadReport('${reportId}', 'json')">
                    <i class="fas fa-file-code"></i> JSON
                </button>
            </div>
        `;
    }

    resultsDiv.innerHTML = html;
}

function updateProgressBar(percent) {
    const progressBar = document.getElementById("progressBar");
    if (progressBar) {
        progressBar.style.width = `${percent}%`;
    }
}

function toggleVuln(index) {
    const content = document.getElementById(`vuln-${index}`);
    if (content) {
        content.classList.toggle("active");
    }
}

function getSeverityColor(severity) {
    const colors = {
        critical: "#ef4444",
        high: "#f59e0b",
        medium: "#3b82f6",
        low: "#10b981",
        info: "#6b7280"
    };
    return colors[severity] || colors.info;
}

function getSeverityClass(severity) {
    const classes = {
        critical: "critical",
        high: "high",
        medium: "medium",
        low: "low",
        info: "info"
    };
    return classes[severity] || "info";
}

async function downloadReport(scanId, format) {
    try {
        const response = await fetch(`${API_BASE_URL}/scan/${scanId}/report/${format}`);

        if (!response.ok) {
            const err = await response.json().catch(() => ({}));
            showNotification(err.detail || "Hisobot yuklashda xatolik", "error");
            return;
        }

        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement("a");

        a.href = url;
        a.download = `scan-report-${scanId}.${format}`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        window.URL.revokeObjectURL(url);

        showNotification("Hisobot yuklanmoqda", "success");
    } catch (error) {
        console.error("Download error:", error);
        showNotification("Hisobot yuklashda xatolik", "error");
    }
}

async function loadRecentScans() {
    const scansList = document.getElementById("scansList");
    if (!scansList) return;

    try {
        const response = await fetch(`${API_BASE_URL}/scans?limit=5`);
        const scans = await response.json().catch(() => []);

        if (!response.ok) {
            scansList.innerHTML = `<p class="loading">Ma'lumotlarni yuklashda xatolik</p>`;
            return;
        }

        if (!Array.isArray(scans) || scans.length === 0) {
            scansList.innerHTML = `<p class="loading">Hali skanerlanmagan</p>`;
            return;
        }

        let html = "";
        scans.forEach(scan => {
            html += `
                <div class="scan-item">
                    <div class="scan-info">
                        <h3>${escapeHtml(scan.target_url || scan.url || "Noma'lum target")}</h3>
                        <div class="scan-meta">
                            <span><i class="far fa-calendar"></i> ${formatDate(scan.start_time || scan.created_at)}</span>
                            <span><i class="fas fa-shield"></i> ${escapeHtml(scan.scan_type || "unknown")}</span>
                        </div>
                    </div>
                    <div class="scan-status status-${escapeHtml(scan.status || "unknown")}">
                        ${scan.status === "completed" ? "✅" : "⏳"} ${escapeHtml(scan.status || "unknown")}
                    </div>
                </div>
            `;
        });

        scansList.innerHTML = html;
    } catch (error) {
        console.error("Load scans error:", error);
        scansList.innerHTML = `<p class="loading">Ma'lumotlarni yuklashda xatolik</p>`;
    }
}

function openLoginModal() {
    const el = document.getElementById("loginModal");
    if (el) el.classList.add("active");
}

function closeLoginModal() {
    const el = document.getElementById("loginModal");
    if (el) el.classList.remove("active");
}

function openRegisterModal() {
    const el = document.getElementById("registerModal");
    if (el) el.classList.add("active");
}

function closeRegisterModal() {
    const el = document.getElementById("registerModal");
    if (el) el.classList.remove("active");
}

function openScanModal() {
    const modal = document.getElementById("scanModal");
    const resultsContent = document.getElementById("resultsContent");

    if (modal) modal.classList.add("active");
    if (resultsContent) resultsContent.innerHTML = "";
    updateProgressBar(10);
}

function closeScanModal() {
    const el = document.getElementById("scanModal");
    if (el) el.classList.remove("active");
}

async function handleLogin(event) {
    event.preventDefault();

    const email = document.getElementById("loginEmail")?.value.trim();
    const password = document.getElementById("loginPassword")?.value;

    console.log("Login:", { email, password });
    showNotification("Login API hali ulanmagan", "info");
}

async function handleRegister(event) {
    event.preventDefault();

    const name = document.getElementById("registerName")?.value.trim();
    const email = document.getElementById("registerEmail")?.value.trim();
    const password = document.getElementById("registerPassword")?.value;
    const confirmPassword = document.getElementById("registerConfirmPassword")?.value;

    if (password !== confirmPassword) {
        showNotification("Parollar mos kelmadi", "error");
        return;
    }

    console.log("Register:", { name, email, password });
    showNotification("Register API hali ulanmagan", "info");
}

function showNotification(message, type = "info") {
    const notification = document.createElement("div");
    notification.className = `notification notification-${type}`;
    notification.innerHTML = `
        <i class="fas ${type === "success" ? "fa-check-circle" : type === "error" ? "fa-exclamation-circle" : "fa-info-circle"}"></i>
        <span>${escapeHtml(message)}</span>
    `;

    notification.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        padding: 1rem 2rem;
        background: ${type === "success" ? "#10b981" : type === "error" ? "#ef4444" : "#3b82f6"};
        color: white;
        border-radius: 5px;
        box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        z-index: 3000;
        animation: slideIn 0.3s ease;
    `;

    document.body.appendChild(notification);

    setTimeout(() => {
        notification.style.animation = "slideOut 0.3s ease";
        setTimeout(() => {
            if (notification.parentNode) {
                document.body.removeChild(notification);
            }
        }, 300);
    }, 3000);
}

async function loadVulnerabilityTypes() {
    try {
        const response = await fetch(`${API_BASE_URL}/vulnerability-types`);
        if (!response.ok) return;

        const types = await response.json().catch(() => []);
        console.log("Vulnerability types:", types);
    } catch (error) {
        console.error("Load types error:", error);
    }
}

function formatDate(dateString) {
    if (!dateString) return "Noma'lum vaqt";
    const date = new Date(dateString);
    if (isNaN(date.getTime())) return "Noma'lum vaqt";
    return date.toLocaleString();
}

function escapeHtml(value) {
    return String(value)
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
}

document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
        closeLoginModal();
        closeRegisterModal();
        closeScanModal();
    }
});