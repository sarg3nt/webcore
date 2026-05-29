package ui

import (
	"io/fs"
	"testing"
)

// TestStaticFilesEmbedsExpected guards that the embedded asset surface includes
// the files consumers reference by path (the toast container loads
// /static/js/utils/toast.js, etc.). A missing file here means a 404 at runtime.
func TestStaticFilesEmbedsExpected(t *testing.T) {
	want := []string{
		"static/js/utils/toast.js",
		"static/js/utils/dom.js",
		"static/js/utils/formatting.js",
		"static/js/utils/char-limit.js",
		"static/js/common/sse.js",
		"static/js/common/focus-trap.js",
		"static/js/common/keymap.js",
		"static/js/common/page-header.js",
		"static/js/common/info-tooltip.js",
		"static/js/common/datagrid.js",
		"static/css/utilities.css",
		"static/css/components/buttons.css",
		"static/css/components/cards.css",
		"static/css/components/modals.css",
		"static/css/components/datagrid.css",
	}
	for _, p := range want {
		if _, err := fs.Stat(StaticFiles, p); err != nil {
			t.Errorf("embedded asset missing: %s (%v)", p, err)
		}
	}
}

// TestSubFSMounts confirms the fs.Sub used by consumers resolves a known file.
func TestSubFSMounts(t *testing.T) {
	sub, err := fs.Sub(StaticFiles, "static")
	if err != nil {
		t.Fatalf("fs.Sub: %v", err)
	}
	if _, err := fs.Stat(sub, "js/utils/toast.js"); err != nil {
		t.Errorf("sub FS should resolve js/utils/toast.js: %v", err)
	}
}
