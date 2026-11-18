
// REPOSHIELD SAMPLE DATA

const findings = [
    {
        issue: "SQL injection in database query",
        severity: "Critical",
        file: "src/routes/users.py",
        line: 42,
        scanner: "Code analysis"
    },
    {
        issue: "OS command injection",
        severity: "Critical",
        file: "src/utils/export.py",
        line: 67,
        scanner: "Code analysis"
    },
    {
        issue: "Hardcoded API credential",
        severity: "High",
        file: "config/settings.py",
        line: 18,
        scanner: "Secrets"
    },
    {
        issue: "Unpinned third-party action",
        severity: "Medium",
        file: ".github/workflows/ci.yml",
        line: 24,
        scanner: "GitHub Actions"
    },
    {
        issue: "Missing container health check",
        severity: "Low",
        file: "Dockerfile",
        line: 1,
        scanner: "Docker security"
    }
];


// NAVIGATION

const pageNames = {
    dashboard: "Dashboard",
    scan: "Scan Repository",
    results: "Vulnerabilities",
    finding: "Finding details",
    reports: "Reports",
    secrets: "Secrets",
    docker: "Docker Security",
    github: "GitHub Actions",
    settings: "Settings"
};

function showPage(page) {

    document.querySelectorAll(".page").forEach(section => {
        section.classList.remove("active");
    });

    const selectedPage = document.getElementById("page-" + page);

    if (!selectedPage) return;

    selectedPage.classList.add("active");

    document.getElementById("breadcrumb").textContent =
        pageNames[page];

    document.querySelectorAll(".nav-item").forEach(button => {
        button.classList.toggle(
            "active",
            button.dataset.page === page
        );
    });

    window.scrollTo(0, 0);
}


// NAVIGATION BUTTONS

document.addEventListener("click", function(event) {

    const navButton = event.target.closest("[data-page]");

    if (navButton) {
        showPage(navButton.dataset.page);
    }

    const goButton = event.target.closest("[data-go]");

    if (goButton) {
        showPage(goButton.dataset.go);
    }

    const findingButton = event.target.closest("[data-finding]");

    if (findingButton) {
        showPage("finding");
    }

    const downloadButton = event.target.closest("[data-download]");

    if (downloadButton) {
        downloadReport(
            downloadButton.dataset.download,
            Number(downloadButton.dataset.index)
        );
    }

});


// SEVERITY BADGES

function severityBadge(severity) {

    return `
        <span class="severity sev-${severity}">
            ${severity}
        </span>
    `;
}


// DASHBOARD FINDINGS TABLE

function loadDashboardFindings() {

    const table = document.getElementById("dashboard-findings");

    table.innerHTML = findings.slice(0, 4).map(item => {

        return `
            <tr>
                <td>${item.issue}</td>

                <td>${severityBadge(item.severity)}</td>

                <td>${item.file}</td>

                <td>${item.scanner}</td>

                <td>
                    <button class="row-action" data-finding>
                        View →
                    </button>
                </td>
            </tr>
        `;

    }).join("");
}


// SCAN RESULTS TABLE

function loadResults() {

    const table = document.getElementById("results-findings");

    table.innerHTML = findings.map(item => {

        return `
            <tr>
                <td>${item.issue}</td>

                <td>${severityBadge(item.severity)}</td>

                <td>${item.file}</td>

                <td>${item.line}</td>

                <td>
                    <button class="row-action" data-finding>
                        View details
                    </button>
                </td>
            </tr>
        `;

    }).join("");
}


// RECENT SCAN HISTORY

function loadHistory() {

    const history = [
        ["api-service", "Today, 10:42 AM", "24 findings", "72 / 100"],
        ["web-client", "Yesterday, 4:18 PM", "8 findings", "88 / 100"],
        ["task-worker", "16 Nov 2026", "3 findings", "94 / 100"]
    ];

    const container = document.getElementById("recent-history");

    container.innerHTML = history.map(item => {

        return `
            <div class="history-row">
                <strong>${item[0]}</strong>
                <small>${item[1]}</small>
                <span>${item[2]}</span>
                <b>${item[3]}</b>
            </div>
        `;

    }).join("");
}


// REPORT HISTORY

const reports = [
    ["api-service", "18 Nov 2026", 24, "72 / 100"],
    ["web-client", "17 Nov 2026", 8, "88 / 100"],
    ["task-worker", "16 Nov 2026", 3, "94 / 100"],
    ["api-service", "15 Nov 2026", 31, "64 / 100"],
    ["web-client", "14 Nov 2026", 12, "81 / 100"],
    ["task-worker", "13 Nov 2026", 7, "87 / 100"]
];

function loadReports(search = "") {

    const table = document.getElementById("reports-table");

    table.innerHTML = reports
        .map((item, index) => ({item, index}))
        .filter(row => row.item[0].toLowerCase().includes(search.toLowerCase()))
        .map(({item, index}) => {

            return `
                <tr>
                    <td>${item[0]}</td>

                    <td>${item[1]}</td>

                    <td>${item[2]} findings</td>

                    <td>${item[3]}</td>

                    <td>
                        <button class="download-btn"
                            data-download="pdf"
                            data-index="${index}">
                            Download PDF
                        </button>

                        <button class="download-btn"
                            data-download="json"
                            data-index="${index}">
                            Download JSON
                        </button>
                    </td>
                </tr>
            `;

        }).join("");
}


// REPORT SEARCH

const reportSearch = document.getElementById("report-search");

if (reportSearch) {
    reportSearch.addEventListener("input", function() {
        loadReports(this.value);
    });
}


// ZIP FILE UPLOAD

const fileInput = document.getElementById("zip-file");

function showSelectedFile(file) {

    if (!file) return;

    if (!file.name.toLowerCase().endsWith(".zip")) {
        alert("Please select a ZIP file.");
        fileInput.value = "";
        return;
    }

    if (file.size > 100 * 1024 * 1024) {
        alert("Maximum file size is 100 MB.");
        fileInput.value = "";
        return;
    }

    document.getElementById("upload-title").textContent = file.name;

    document.getElementById("selected-file").textContent =
        file.name + " · " +
        (file.size / 1024 / 1024).toFixed(2) +
        " MB · Ready to scan";
}

fileInput.addEventListener("change", function() {
    showSelectedFile(this.files[0]);
});


// DRAG AND DROP

const dropZone = document.getElementById("drop-zone");

dropZone.addEventListener("dragover", function(event) {
    event.preventDefault();
    dropZone.classList.add("dragover");
});

dropZone.addEventListener("dragleave", function() {
    dropZone.classList.remove("dragover");
});

dropZone.addEventListener("drop", function(event) {

    event.preventDefault();

    dropZone.classList.remove("dragover");

    const file = event.dataTransfer.files[0];

    if (file) {
        showSelectedFile(file);
    }

});


// SCAN BUTTON

document.getElementById("scan-button").addEventListener("click", function() {

    const status = document.getElementById("scan-status");

    status.textContent = "Demo scan completed! Showing sample results.";

    setTimeout(function() {
        showPage("results");
    }, 800);

});


// REPORT DOWNLOAD

function downloadReport(type, index) {

    const report = reports[index];

    const data = {
        repository: report[0],
        scan_date: report[1],
        findings: findings,
        security_score: report[3],
        note: "Illustrative demo data, not a real scan."
    };

    if (type === "json") {

        const blob = new Blob(
            [JSON.stringify(data, null, 2)],
            {type: "application/json"}
        );

        const url = URL.createObjectURL(blob);

        const link = document.createElement("a");

        link.href = url;
        link.download = report[0] + "-report.json";

        link.click();

        URL.revokeObjectURL(url);

    } else {

        window.print();

    }

}


// LOAD INITIAL DATA

loadDashboardFindings();
loadResults();
loadHistory();
loadReports();
