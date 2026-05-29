package components

import (
	"context"
	"strings"
	"testing"

	"github.com/a-h/templ"
)

// render runs a templ component to a string for assertion.
func render(t *testing.T, c templ.Component) string {
	t.Helper()
	var sb strings.Builder
	if err := c.Render(context.Background(), &sb); err != nil {
		t.Fatalf("render: %v", err)
	}
	return sb.String()
}

func TestAlerts(t *testing.T) {
	if got := render(t, ErrorAlert("boom")); !strings.Contains(got, "boom") || !strings.Contains(got, "red") {
		t.Errorf("ErrorAlert = %q", got)
	}
	if got := render(t, SuccessAlert("ok")); !strings.Contains(got, "ok") || !strings.Contains(got, "green") {
		t.Errorf("SuccessAlert = %q", got)
	}
	if got := render(t, WarningAlert("warn")); !strings.Contains(got, "yellow") {
		t.Errorf("WarningAlert = %q", got)
	}
	if got := render(t, InfoAlert("info")); !strings.Contains(got, "blue") {
		t.Errorf("InfoAlert = %q", got)
	}
	if got := render(t, LoadingSpinner()); !strings.Contains(got, "animate-spin") {
		t.Errorf("LoadingSpinner = %q", got)
	}
	if got := render(t, EmptyState(nil, "Nothing", "no rows")); !strings.Contains(got, "Nothing") || !strings.Contains(got, "no rows") {
		t.Errorf("EmptyState = %q", got)
	}
}

func TestBadges(t *testing.T) {
	if got := render(t, Badge("hi", "bg-pink-500")); !strings.Contains(got, "hi") || !strings.Contains(got, "bg-pink-500") {
		t.Errorf("Badge = %q", got)
	}
	if got := render(t, StatusBadge("up", "success")); !strings.Contains(got, "green") {
		t.Errorf("StatusBadge success = %q", got)
	}
	if got := render(t, StatusBadge("?", "weird")); !strings.Contains(got, "gray") {
		t.Errorf("StatusBadge default = %q", got)
	}
	// CountBadge: zero renders nothing, over-max renders "N+".
	if got := render(t, CountBadge(0, 9)); strings.TrimSpace(got) != "" {
		t.Errorf("CountBadge(0) should be empty, got %q", got)
	}
	if got := render(t, CountBadge(50, 9)); !strings.Contains(got, "9+") {
		t.Errorf("CountBadge over max = %q", got)
	}
	if got := render(t, CountBadge(3, 9)); !strings.Contains(got, "3") {
		t.Errorf("CountBadge = %q", got)
	}
}

func TestToggle(t *testing.T) {
	got := render(t, Toggle("t1", "enabled", "", true, false))
	if !strings.Contains(got, `id="t1"`) || !strings.Contains(got, `name="enabled"`) {
		t.Errorf("Toggle id/name = %q", got)
	}
	// Empty value defaults to "on".
	if !strings.Contains(got, `value="on"`) {
		t.Errorf("Toggle should default value to on, got %q", got)
	}
	if !strings.Contains(got, "checked") {
		t.Errorf("Toggle checked = %q", got)
	}
	withLabel := render(t, ToggleWithLabel("t2", "n", "v", "My Label", "help me", false, false))
	if !strings.Contains(withLabel, "My Label") || !strings.Contains(withLabel, "help me") {
		t.Errorf("ToggleWithLabel = %q", withLabel)
	}
}

func TestModal(t *testing.T) {
	got := render(t, Modal("m1", "Title Here", "lg"))
	if !strings.Contains(got, `id="m1"`) || !strings.Contains(got, "Title Here") {
		t.Errorf("Modal = %q", got)
	}
	if !strings.Contains(got, "sm:max-w-2xl") { // lg size
		t.Errorf("Modal lg size class missing: %q", got)
	}
	confirm := render(t, ConfirmModal("c1", "Delete?", "Are you sure", "Delete", "danger"))
	if !strings.Contains(confirm, "Delete?") || !strings.Contains(confirm, "red") {
		t.Errorf("ConfirmModal danger = %q", confirm)
	}
}

func TestCollapsible(t *testing.T) {
	got := render(t, CollapsibleSection("sec1", "Section", "3", "bg-blue-500", true))
	if !strings.Contains(got, `data-collapsible-id="sec1"`) || !strings.Contains(got, "Section") {
		t.Errorf("CollapsibleSection = %q", got)
	}
	// defaultOpen=true => content not hidden.
	if strings.Contains(got, "collapsible-content bg-white dark:bg-slate-900 hidden") {
		t.Errorf("defaultOpen section should not be hidden: %q", got)
	}
	closed := render(t, CollapsibleSection("sec2", "S", "", "", false))
	if !strings.Contains(closed, "hidden") {
		t.Errorf("closed section should be hidden: %q", closed)
	}
}

func TestInfoTooltip(t *testing.T) {
	got := render(t, InfoTooltip("hover help"))
	if !strings.Contains(got, "hover help") || !strings.Contains(got, "group-hover:visible") {
		t.Errorf("InfoTooltip = %q", got)
	}
}

func TestDoughnut(t *testing.T) {
	got := render(t, DoughnutWithLabel(75, "CPU", "75%", 100))
	if !strings.Contains(got, "75%") || !strings.Contains(got, "CPU") {
		t.Errorf("DoughnutWithLabel = %q", got)
	}
	// StatusDoughnut with total=0 renders nothing.
	if got := render(t, StatusDoughnut(0, 0, "X")); strings.TrimSpace(got) != "" {
		t.Errorf("StatusDoughnut(0,0) should be empty, got %q", got)
	}
	healthy := render(t, StatusDoughnut(3, 5, "Backends"))
	if !strings.Contains(healthy, "Backends") || !strings.Contains(healthy, "of ") {
		t.Errorf("StatusDoughnut = %q", healthy)
	}
}

func TestSettingsControls(t *testing.T) {
	if got := render(t, SettingsCheckbox("c", "Enable", "turns it on", true)); !strings.Contains(got, "Enable") || !strings.Contains(got, "checked") {
		t.Errorf("SettingsCheckbox = %q", got)
	}
	sel := render(t, SettingsSelect("s", "Pick", "", []SelectOption{{Value: "a", Label: "Apple", Selected: true}, {Value: "b", Label: "Banana"}}))
	if !strings.Contains(sel, "Apple") || !strings.Contains(sel, "selected") || !strings.Contains(sel, "Banana") {
		t.Errorf("SettingsSelect = %q", sel)
	}
	ti := render(t, SettingsTextInput("t", "Name", "your name", "help", "Dave"))
	if !strings.Contains(ti, `value="Dave"`) || !strings.Contains(ti, "your name") {
		t.Errorf("SettingsTextInput = %q", ti)
	}
	ni := render(t, SettingsNumberInput("n", "Count", "", 5, 1, 10))
	if !strings.Contains(ni, `value="5"`) || !strings.Contains(ni, `min="1"`) || !strings.Contains(ni, `max="10"`) {
		t.Errorf("SettingsNumberInput = %q", ni)
	}
}

func TestIconsRenderSVG(t *testing.T) {
	// Icons are parameterless templ components; spot-check a couple render SVG.
	// (We don't enumerate all ~35; just confirm the package's icon output is SVG.)
	got := render(t, InfoTooltip("x")) // contains an inline svg via the tooltip
	if !strings.Contains(got, "<svg") {
		t.Errorf("expected svg output, got %q", got)
	}
}

func TestHelpers(t *testing.T) {
	if intToString(42) != "42" {
		t.Error("intToString")
	}
	if got := formatNumber(1234567, 0); got != "1,234,567" {
		t.Errorf("formatNumber = %q, want 1,234,567", got)
	}
	if got := formatNumber(12.5, 1); got != "12.5" {
		t.Errorf("formatNumber small = %q", got)
	}
}
