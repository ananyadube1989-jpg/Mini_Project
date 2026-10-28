const fileInput = document.getElementById("file-input");
const dropZone = document.getElementById("drop-zone");
const dropText = document.getElementById("drop-text");
const scanButton = document.getElementById("scan-button");

let selectedFile = null;

function selectFile(file) {
    selectedFile = file || null;
    dropText.textContent = selectedFile
        ? selectedFile.name + " (" + formatSize(selectedFile.size) + ")"
        : "Drag a file here, or click to choose one";
    scanButton.disabled = !selectedFile;
}

fileInput.addEventListener("change", () => selectFile(fileInput.files[0]));

dropZone.addEventListener("dragover", event => {
    event.preventDefault();
    dropZone.classList.add("dragging");
});

dropZone.addEventListener("dragleave", () => dropZone.classList.remove("dragging"));

dropZone.addEventListener("drop", event => {
    event.preventDefault();
    dropZone.classList.remove("dragging");
    selectFile(event.dataTransfer.files[0]);
});

scanButton.addEventListener("click", async () => {
    if (!selectedFile) {
        return;
    }

    scanButton.disabled = true;
    scanButton.textContent = "Scanning...";

    try {
        const response = await fetch("/api/scan", {
            method: "POST",
            headers: { "X-Filename": encodeURIComponent(selectedFile.name) },
            body: selectedFile
        });

        if (!response.ok) {
            throw new Error("Server returned " + response.status);
        }

        showResult(await response.json());
        loadHistory();
    } catch (error) {
        alert("Scan failed: " + error.message);
    } finally {
        scanButton.textContent = "Scan file";
        scanButton.disabled = !selectedFile;
    }
});

function showResult(result) {
    document.getElementById("result").classList.remove("hidden");
    document.getElementById("result-name").textContent = result.filename;

    const badge = document.getElementById("result-risk");
    badge.textContent = result.risk;
    badge.className = "badge " + result.risk;

    const message = document.getElementById("result-message");

    if (result.risk === "ERROR") {
        message.textContent = "The file could not be scanned, so it was not shared.";
        message.className = "note bad";
    } else if (result.blocked) {
        message.textContent = "High risk: this file was blocked and will not be shared.";
        message.className = "note bad";
    } else if (result.risk === "CLEAN") {
        message.textContent = "No warning signs found. The file is ready to share.";
        message.className = "note ok";
    } else {
        message.textContent = "Some warning signs were found. The file can be shared, but the recipient will see this warning.";
        message.className = "note warn";
    }

    document.getElementById("result-size").textContent = formatSize(result.size);
    document.getElementById("result-hash").textContent = result.hash || "-";
    document.getElementById("result-reasons").textContent = result.reasons || "None";
    document.getElementById("result-previous").textContent = result.previousScans > 0
        ? result.previousScans + " time(s), last rated " + result.previousRisk
        : "No, this is a new file";

    const shareBox = document.getElementById("share-box");

    if (result.shareId) {
        document.getElementById("share-link").value = shareUrl(result.shareId);
        shareBox.classList.remove("hidden");
    } else {
        shareBox.classList.add("hidden");
    }
}

document.getElementById("copy-button").addEventListener("click", async () => {
    const link = document.getElementById("share-link");

    try {
        await navigator.clipboard.writeText(link.value);
    } catch (error) {
        link.select();
        document.execCommand("copy");
    }
});

async function loadHistory() {
    const response = await fetch("/api/history");
    const records = await response.json();
    const body = document.getElementById("history-body");

    body.replaceChildren();

    if (records.length === 0) {
        const row = body.insertRow();
        const cell = row.insertCell();
        cell.colSpan = 6;
        cell.className = "empty";
        cell.textContent = "No scans yet";
        return;
    }

    for (const record of records) {
        const row = body.insertRow();

        const name = row.insertCell();
        name.className = "name";
        name.textContent = record.filename;

        row.insertCell().textContent = formatSize(record.size);

        const badge = document.createElement("span");
        badge.className = "badge " + record.risk;
        badge.textContent = record.risk;
        row.insertCell().appendChild(badge);

        row.insertCell().textContent = record.reasons || "None";
        row.insertCell().textContent = record.timestamp.replace("T", " ").substring(0, 19);

        const share = row.insertCell();

        if (record.shareId) {
            const link = document.createElement("a");
            link.href = shareUrl(record.shareId);
            link.textContent = "Open";
            share.appendChild(link);
        } else {
            share.textContent = "Blocked";
        }
    }
}

function shareUrl(shareId) {
    return location.origin + "/share/" + shareId;
}

function formatSize(bytes) {
    if (bytes < 1024) return bytes + " B";
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + " KB";
    return (bytes / (1024 * 1024)).toFixed(1) + " MB";
}

loadHistory();
