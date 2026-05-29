package components

import (
	"strings"
	"testing"
)

func TestSortableTableHeader(t *testing.T) {
	cols := []TableColumn{
		{Key: "name", Label: "Name", Sortable: true, DataType: "string"},
		{Key: "size", Label: "Size", Sortable: false, Alignment: "right"},
	}
	got := render(t, SortableTableHeader("tbl", cols, "name", "asc"))
	if !strings.Contains(got, "Name") || !strings.Contains(got, "Size") {
		t.Errorf("headers missing: %q", got)
	}
	// Sortable column wires an onclick to sortTable; non-sortable does not.
	if !strings.Contains(got, "sortTable('tbl', 'name'") {
		t.Errorf("sortable header should call sortTable: %q", got)
	}
	if !strings.Contains(got, `data-sort-key="name"`) {
		t.Errorf("sortable header should carry data-sort-key: %q", got)
	}
}

func TestTableToolbar(t *testing.T) {
	cfg := TableConfig{ID: "tbl", Title: "Widgets", Description: "all widgets", EnableSearch: true, EnableExport: true}
	got := render(t, TableToolbar("tbl", cfg))
	if !strings.Contains(got, "Widgets") || !strings.Contains(got, "all widgets") {
		t.Errorf("toolbar title/desc: %q", got)
	}
	if !strings.Contains(got, "filterTable('tbl'") {
		t.Errorf("search input should call filterTable: %q", got)
	}
	if !strings.Contains(got, "exportTableCSV('tbl'") {
		t.Errorf("export button should call exportTableCSV: %q", got)
	}
	if !strings.Contains(got, `maxlength="100"`) {
		t.Errorf("search input should cap length: %q", got)
	}
}

func TestTablePagination(t *testing.T) {
	got := render(t, TablePagination("tbl", 25))
	if !strings.Contains(got, "tbl-pagination") || !strings.Contains(got, "changePageSize('tbl'") {
		t.Errorf("pagination = %q", got)
	}
}

func TestEnhancedTableScriptsSelfContained(t *testing.T) {
	got := render(t, EnhancedTableScripts())
	// The export no-data path must not call a gearbox-global unguarded.
	if strings.Contains(got, "showAlertDialog({") && !strings.Contains(got, "window.showAlertDialog") {
		t.Errorf("showAlertDialog should be guarded by window. check: %q", got)
	}
	for _, fn := range []string{"function sortTable", "function filterTable", "function exportTableCSV"} {
		if !strings.Contains(got, fn) {
			t.Errorf("table script missing %s", fn)
		}
	}
}

func TestLiveRefreshButton(t *testing.T) {
	got := render(t, LiveRefreshButton())
	if !strings.Contains(got, `id="refresh-btn"`) || !strings.Contains(got, "manualRefresh()") {
		t.Errorf("LiveRefreshButton = %q", got)
	}
	script := render(t, LiveRefreshButtonScript())
	if !strings.Contains(script, "function updateSSEStatus") {
		t.Errorf("LiveRefreshButtonScript missing updateSSEStatus: %q", script)
	}
}

func TestToast(t *testing.T) {
	got := render(t, Toast())
	if !strings.Contains(got, `id="toast-container"`) || !strings.Contains(got, "top-4 right-4") {
		t.Errorf("Toast container = %q", got)
	}
	if !strings.Contains(got, "/static/js/utils/toast.js") {
		t.Errorf("Toast should load toast.js: %q", got)
	}
	onload := render(t, ToastOnLoad("hello", "success"))
	if !strings.Contains(onload, `data-toast-message="hello"`) || !strings.Contains(onload, `data-toast-type="success"`) {
		t.Errorf("ToastOnLoad = %q", onload)
	}
}

func TestMetricCard(t *testing.T) {
	got := render(t, MetricCard("CPU", "42", "%"))
	if !strings.Contains(got, "CPU") || !strings.Contains(got, "42") || !strings.Contains(got, "%") {
		t.Errorf("MetricCard = %q", got)
	}
	sub := render(t, MetricCardWithSubValue("Net", "10", "20", "MB/s"))
	if !strings.Contains(sub, "10") || !strings.Contains(sub, "20") || !strings.Contains(sub, "MB/s") {
		t.Errorf("MetricCardWithSubValue = %q", sub)
	}
}
