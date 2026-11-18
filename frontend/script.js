const API_URL = "http://127.0.0.1:8000/scan";

// Get HTML elements
const fileInput = document.getElementById("repositoryFile");
const scanButton = document.getElementById("scanButton");

const scoreElement = document.getElementById("securityScore");
const findingsCountElement = document.getElementById("totalFindings");
const statusElement = document.getElementById("status");
const scanStatusElement = document.getElementById("scanStatus");
const findingsTable = document.getElementById("findingsTable");

// Display findings in the table
function displayFindings(findings) {
    findingsTable.replaceChildren();

    if (!findings || findings.length === 0) {
        const row = document.createElement("tr");
        const cell = document.createElement("td");

        cell.colSpan = 4;
        cell.textContent = "No security findings detected.";

        row.appendChild(cell);
        findingsTable.appendChild(row);
        return;
    }

    findings.forEach((finding) => {
        const row = document.createElement("tr");

        const values = [
            finding.type || finding.title || "Unknown finding",
            finding.scanner || "Unknown",
            finding.severity || "UNKNOWN",
            finding.file || finding.file_path || "Not specified"
        ];

        values.forEach((value) => {
            const cell = document.createElement("td");
            cell.textContent = value;
            row.appendChild(cell);
        });

        findingsTable.appendChild(row);
    });
}

// Scan button functionality
scanButton.addEventListener("click", async () => {

    const file = fileInput.files[0];

    // Check whether a file was selected
    if (!file) {
        scanStatusElement.textContent = "Please select a ZIP file first.";
        return;
    }

    // Check file extension
    if (!file.name.toLowerCase().endsWith(".zip")) {
        scanStatusElement.textContent = "Only ZIP files are allowed.";
        return;
    }

    // Check 20 MB limit
    if (file.size > 20 * 1024 * 1024) {
        scanStatusElement.textContent = "File exceeds the 20 MB limit.";
        return;
    }

    // Prepare ZIP file for upload
    const formData = new FormData();
    formData.append("file", file);

    try {
        scanButton.disabled = true;
        scanButton.textContent = "Scanning...";
        scanStatusElement.textContent = "Uploading repository and scanning...";
        statusElement.textContent = "Scanning";

        // Send request to FastAPI
        const response = await fetch(API_URL, {
            method: "POST",
            body: formData
        });

        const result = await response.json();

        // Handle backend errors
        if (!response.ok) {
            throw new Error(
                result.detail || "Something went wrong during scanning."
            );
        }

        // Display total findings
        findingsCountElement.textContent = result.total_findings ?? 0;

        // Display security score
        scoreElement.textContent =
            result.security_score === null
                ? "--"
                : `${result.security_score}/100`;

        // Display scan status
        statusElement.textContent = result.status;

        // Display findings
        displayFindings(result.findings);

        // Handle completed and partial scans
        if (result.status === "completed") {
            scanStatusElement.textContent =
                `Scan completed successfully! Scan ID: ${result.scan_id}`;
        } else {
            const errors = (result.scanner_errors || [])
                .map(error =>
                    typeof error === "string"
                        ? error
                        : error.message || JSON.stringify(error)
                )
                .join("; ");

            scanStatusElement.textContent =
                `Partial scan completed. Some scanners failed: ${errors}`;
        }

    } catch (error) {
        console.error("Scan error:", error);

        scanStatusElement.textContent =
            `Error: ${error.message}`;

        statusElement.textContent = "Failed";

    } finally {
        scanButton.disabled = false;
        scanButton.textContent = "Scan Repository";
    }
});