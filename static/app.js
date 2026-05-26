document.addEventListener("DOMContentLoaded", () => {
    // DOM Elements
    const codeEditor = document.getElementById("code-editor");
    const lineNumbers = document.getElementById("line-numbers");
    const templateSelect = document.getElementById("template-select");
    const frameworkSelect = document.getElementById("framework-select");
    const scanBtn = document.getElementById("scan-btn");
    const findingsContainer = document.getElementById("findings-container");

    // Metrics elements
    const metricFiles = document.getElementById("metric-files");
    const metricBugs = document.getElementById("metric-bugs");
    const metricCritical = document.getElementById("metric-critical");
    const metricLatency = document.getElementById("metric-latency");

    let templates = {};

    // 1. Synchronize Line Numbers
    function updateLineNumbers() {
        const text = codeEditor.value;
        const lines = text.split("\n");
        const count = lines.length;
        
        let html = "";
        for (let i = 1; i <= count; i++) {
            html += `<div>${i}</div>`;
        }
        lineNumbers.innerHTML = html;
    }

    // Scroll synchronization
    codeEditor.addEventListener("scroll", () => {
        lineNumbers.scrollTop = codeEditor.scrollTop;
    });

    // Trigger update on typing/key presses
    codeEditor.addEventListener("input", updateLineNumbers);

    // 2. Load Templates
    async function loadTemplates() {
        try {
            const response = await fetch("/api/templates");
            if (response.ok) {
                templates = await response.json();
                // Load default (flask) template
                loadTemplate("flask");
            }
        } catch (e) {
            console.error("Failed to load templates:", e);
        }
    }

    function loadTemplate(key) {
        if (templates[key]) {
            codeEditor.value = templates[key];
            updateLineNumbers();
            
            // Sync framework dropdown
            frameworkSelect.value = key;
        }
    }

    templateSelect.addEventListener("change", (e) => {
        loadTemplate(e.target.value);
    });

    // 3. Render Findings Cards
    function renderFindings(findings) {
        findingsContainer.innerHTML = "";

        if (findings.length === 0) {
            findingsContainer.innerHTML = `
                <div class="all-safe-screen">
                    <span class="success-check">💚</span>
                    <h3>AST Scan Clean</h3>
                    <p>No vulnerabilities or security gaps were flagged. Your codebase matches all security checks perfectly!</p>
                </div>
            `;
            return;
        }

        findings.forEach(f => {
            const card = document.createElement("div");
            card.className = `finding-card border-glow-${f.severity === 'critical' ? 'red' : f.severity === 'high' ? 'orange' : f.severity === 'medium' ? 'yellow' : 'blue'}`;

            // Create snippet HTML
            let snippetHtml = "";
            if (f.code_snippet) {
                const lines = f.code_snippet.split("\n");
                lines.forEach(lineText => {
                    const isTarget = lineText.includes(">");
                    snippetHtml += `<div class="${isTarget ? 'highlight-line' : ''}">${escapeHtml(lineText)}</div>`;
                });
            }

            let suggestedFixHtml = "";
            if (f.suggested_fix) {
                suggestedFixHtml = `
                    <div class="fix-block">
                        <span class="fix-title">💡 SUGGESTED FIX:</span>
                        <div class="fix-code">${escapeHtml(f.suggested_fix)}</div>
                    </div>
                `;
            }

            card.innerHTML = `
                <div class="finding-header">
                    <span class="finding-rule-id">${escapeHtml(f.rule_id)}</span>
                    <span class="severity-badge sev-${f.severity}">${escapeHtml(f.severity)}</span>
                </div>
                <div class="finding-message">${escapeHtml(f.message)}</div>
                <div class="finding-location">📍 sandbox.py:${f.line}:${f.column}</div>
                ${f.code_snippet ? `<div class="snippet-block">${snippetHtml}</div>` : ""}
                ${suggestedFixHtml}
            `;

            findingsContainer.appendChild(card);
        });
    }

    function escapeHtml(text) {
        if (!text) return "";
        return text
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }

    // 4. Trigger Analysis
    async function runScan() {
        const code = codeEditor.value;
        const framework = frameworkSelect.value;

        // Visual loading trigger
        scanBtn.disabled = true;
        scanBtn.innerHTML = `Scanning...`;

        try {
            const response = await fetch("/api/scan", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({ code, framework })
            });

            if (response.ok) {
                const report = await response.json();
                
                // Update metrics counters
                metricFiles.innerText = report.scanned_files.length;
                metricBugs.innerText = report.findings.length;
                
                // Count criticals
                const criticalCount = report.findings.filter(f => f.severity === 'critical').length;
                metricCritical.innerText = criticalCount;
                
                metricLatency.innerText = `${report.scan_time_seconds.toFixed(4)}s`;

                // Render cards
                renderFindings(report.findings);
            } else {
                alert("Error: Analysis scan request failed.");
            }
        } catch (e) {
            console.error("Scan error:", e);
            alert("Error: Failed to connect to local static analysis server.");
        } finally {
            scanBtn.disabled = false;
            scanBtn.innerHTML = `🔒 RUN LOCAL AUDIT`;
        }
    }

    scanBtn.addEventListener("click", runScan);

    // Initializations
    loadTemplates();
});
