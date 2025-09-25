// Log Monitor Web UI - Main JavaScript

document.addEventListener("DOMContentLoaded", function () {
	// Initialize current time display
	updateCurrentTime();
	setInterval(updateCurrentTime, 1000);

	// Initialize tooltips
	initializeTooltips();

	// Initialize auto-refresh for dashboard
	if (
		window.location.pathname === "/" ||
		window.location.pathname === "/dashboard"
	) {
		initializeAutoRefresh();
	}

	// Initialize search functionality
	initializeSearch();

	// Initialize copy functionality
	initializeCopyButtons();
});

// Update current time display
function updateCurrentTime() {
	const timeElement = document.getElementById("current-time");
	if (timeElement) {
		const now = new Date();
		timeElement.textContent = now.toLocaleString();
	}
}

// Initialize Bootstrap tooltips
function initializeTooltips() {
	const tooltipTriggerList = [].slice.call(
		document.querySelectorAll('[data-bs-toggle="tooltip"]')
	);
	tooltipTriggerList.map(function (tooltipTriggerEl) {
		return new bootstrap.Tooltip(tooltipTriggerEl);
	});
}

// Auto-refresh dashboard data
function initializeAutoRefresh() {
	// Refresh stats every 30 seconds
	setInterval(function () {
		refreshDashboardStats();
	}, 30000);
}

// Refresh dashboard statistics
function refreshDashboardStats() {
	fetch("/api/stats?days=7")
		.then((response) => response.json())
		.then((data) => {
			if (data.error) {
				console.error("Error refreshing stats:", data.error);
				return;
			}

			// Update total logs
			const totalLogsElement = document.querySelector(
				".card.bg-primary .card-title"
			);
			if (totalLogsElement) {
				totalLogsElement.textContent = data.total_logs || 0;
			}

			// Update error logs
			const errorLogsElement = document.querySelector(
				".card.bg-warning .card-title"
			);
			if (errorLogsElement) {
				errorLogsElement.textContent = data.logs_by_type?.error || 0;
			}

			// Update charts if they exist
			updateCharts(data);
		})
		.catch((error) => {
			console.error("Error refreshing dashboard:", error);
		});
}

// Update charts with new data
function updateCharts(data) {
	// Update logs by type chart
	const logsByTypeChart = Chart.getChart("logsByTypeChart");
	if (logsByTypeChart) {
		logsByTypeChart.data.labels = Object.keys(data.logs_by_type || {});
		logsByTypeChart.data.datasets[0].data = Object.values(
			data.logs_by_type || {}
		);
		logsByTypeChart.update();
	}

	// Update top apps chart
	const topAppsChart = Chart.getChart("topAppsChart");
	if (topAppsChart) {
		topAppsChart.data.labels = Object.keys(data.logs_by_app || {});
		topAppsChart.data.datasets[0].data = Object.values(data.logs_by_app || {});
		topAppsChart.update();
	}
}

// Initialize search functionality
function initializeSearch() {
	const searchInput = document.getElementById("search");
	if (searchInput) {
		// Add search suggestions
		searchInput.addEventListener("input", function () {
			const query = this.value;
			if (query.length > 2) {
				showSearchSuggestions(query);
			} else {
				hideSearchSuggestions();
			}
		});

		// Clear search on escape
		searchInput.addEventListener("keydown", function (e) {
			if (e.key === "Escape") {
				this.value = "";
				hideSearchSuggestions();
			}
		});
	}
}

// Show search suggestions
function showSearchSuggestions(query) {
	// This would typically fetch suggestions from the server
	// For now, we'll just show a placeholder
	console.log("Search suggestions for:", query);
}

// Hide search suggestions
function hideSearchSuggestions() {
	// Remove any existing suggestion dropdowns
	const existingDropdown = document.querySelector(".search-suggestions");
	if (existingDropdown) {
		existingDropdown.remove();
	}
}

// Initialize copy buttons
function initializeCopyButtons() {
	// Add copy functionality to code blocks
	const codeBlocks = document.querySelectorAll("code");
	codeBlocks.forEach((block) => {
		if (block.textContent.length > 20) {
			// Only for longer code blocks
			block.style.cursor = "pointer";
			block.title = "Click to copy";
			block.addEventListener("click", function () {
				copyToClipboard(this.textContent);
			});
		}
	});
}

// Copy text to clipboard
function copyToClipboard(text) {
	navigator.clipboard
		.writeText(text)
		.then(function () {
			showToast("Copied to clipboard!", "success");
		})
		.catch(function (err) {
			console.error("Could not copy text: ", err);
			showToast("Failed to copy to clipboard", "error");
		});
}

// Show toast notification
function showToast(message, type = "info") {
	// Create toast element
	const toast = document.createElement("div");
	toast.className = `toast align-items-center text-white bg-${
		type === "error" ? "danger" : type
	} border-0`;
	toast.setAttribute("role", "alert");
	toast.innerHTML = `
        <div class="d-flex">
            <div class="toast-body">
                <i class="fas fa-${
									type === "success"
										? "check-circle"
										: type === "error"
										? "exclamation-circle"
										: "info-circle"
								} me-2"></i>
                ${message}
            </div>
            <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
        </div>
    `;

	// Add to page
	document.body.appendChild(toast);

	// Show toast
	const bsToast = new bootstrap.Toast(toast);
	bsToast.show();

	// Remove after hidden
	toast.addEventListener("hidden.bs.toast", function () {
		toast.remove();
	});
}

// Format file size
function formatFileSize(bytes) {
	if (bytes === 0) return "0 Bytes";

	const k = 1024;
	const sizes = ["Bytes", "KB", "MB", "GB"];
	const i = Math.floor(Math.log(bytes) / Math.log(k));

	return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
}

// Format timestamp
function formatTimestamp(timestamp) {
	const date = new Date(timestamp);
	return date.toLocaleString();
}

// Debounce function for search
function debounce(func, wait) {
	let timeout;
	return function executedFunction(...args) {
		const later = () => {
			clearTimeout(timeout);
			func(...args);
		};
		clearTimeout(timeout);
		timeout = setTimeout(later, wait);
	};
}

// Initialize table sorting
function initializeTableSorting() {
	const tables = document.querySelectorAll("table");
	tables.forEach((table) => {
		const headers = table.querySelectorAll("th[data-sortable]");
		headers.forEach((header) => {
			header.style.cursor = "pointer";
			header.addEventListener("click", function () {
				sortTable(table, this.cellIndex);
			});
		});
	});
}

// Sort table by column
function sortTable(table, columnIndex) {
	const tbody = table.querySelector("tbody");
	const rows = Array.from(tbody.querySelectorAll("tr"));

	rows.sort((a, b) => {
		const aText = a.cells[columnIndex].textContent.trim();
		const bText = b.cells[columnIndex].textContent.trim();

		// Try to parse as numbers first
		const aNum = parseFloat(aText);
		const bNum = parseFloat(bText);

		if (!isNaN(aNum) && !isNaN(bNum)) {
			return aNum - bNum;
		}

		// Otherwise sort as strings
		return aText.localeCompare(bText);
	});

	// Re-append sorted rows
	rows.forEach((row) => tbody.appendChild(row));
}

// Initialize data refresh indicators
function initializeRefreshIndicators() {
	const refreshButtons = document.querySelectorAll("[data-refresh]");
	refreshButtons.forEach((button) => {
		button.addEventListener("click", function () {
			const originalText = this.innerHTML;
			this.innerHTML =
				'<i class="fas fa-spinner fa-spin me-1"></i>Refreshing...';
			this.disabled = true;

			// Simulate refresh delay
			setTimeout(() => {
				this.innerHTML = originalText;
				this.disabled = false;
				showToast("Data refreshed!", "success");
			}, 1000);
		});
	});
}

// Initialize modal functionality
function initializeModals() {
	const modals = document.querySelectorAll(".modal");
	modals.forEach((modal) => {
		modal.addEventListener("show.bs.modal", function () {
			// Add loading state if needed
			const loadingElement = modal.querySelector(".loading-overlay");
			if (loadingElement) {
				loadingElement.style.display = "flex";
			}
		});

		modal.addEventListener("shown.bs.modal", function () {
			// Remove loading state
			const loadingElement = modal.querySelector(".loading-overlay");
			if (loadingElement) {
				loadingElement.style.display = "none";
			}
		});
	});
}

// Initialize all components
function initializeAll() {
	initializeTooltips();
	initializeTableSorting();
	initializeRefreshIndicators();
	initializeModals();
}

// Call initialization when DOM is ready
if (document.readyState === "loading") {
	document.addEventListener("DOMContentLoaded", initializeAll);
} else {
	initializeAll();
}

// Export functions for global use
window.LogMonitor = {
	copyToClipboard,
	showToast,
	formatFileSize,
	formatTimestamp,
	refreshDashboardStats,
};
