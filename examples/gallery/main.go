// Command gallery renders a page of web-core UI components for visual
// inspection during development. Not part of the library; `go run` it and open
// the printed URL.
package main

import (
	"context"
	"io"
	"io/fs"
	"log"
	"net/http"

	"github.com/a-h/templ"
	"github.com/sarg3nt/web-core/ui"
	c "github.com/sarg3nt/web-core/ui/components"
)

func writeStr(w io.Writer, s string) { _, _ = io.WriteString(w, s) }

func section(title string, body templ.Component) templ.Component {
	return templ.ComponentFunc(func(ctx context.Context, w io.Writer) error {
		writeStr(w, `<section class="space-y-3"><h2 class="text-lg font-semibold text-gray-100 border-b border-slate-700 pb-1">`+title+`</h2><div class="space-y-3">`)
		if err := body.Render(ctx, w); err != nil {
			return err
		}
		writeStr(w, `</div></section>`)
		return nil
	})
}

func group(comps ...templ.Component) templ.Component {
	return templ.ComponentFunc(func(ctx context.Context, w io.Writer) error {
		for _, comp := range comps {
			if err := comp.Render(ctx, w); err != nil {
				return err
			}
		}
		return nil
	})
}

func page() templ.Component {
	return templ.ComponentFunc(func(ctx context.Context, w io.Writer) error {
		writeStr(w, `<!DOCTYPE html><html lang="en" class="dark"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>web-core gallery</title><script src="https://cdn.tailwindcss.com"></script><script>tailwind.config={darkMode:'class'}</script></head><body class="bg-slate-900 text-gray-200 p-8"><h1 class="text-2xl font-bold mb-6">web-core component gallery</h1><div class="grid grid-cols-1 md:grid-cols-2 gap-8 max-w-5xl">`)

		sections := []struct {
			title string
			body  templ.Component
		}{
			{"Alerts", group(c.SuccessAlert("Saved successfully"), c.ErrorAlert("Something failed"), c.WarningAlert("Heads up"), c.InfoAlert("For your information"))},
			{"Badges", group(c.StatusBadge("success", "success"), c.StatusBadge("error", "error"), c.StatusBadge("warning", "warning"), c.CountBadge(5, 9), c.CountBadge(50, 9))},
			{"Toggle", c.ToggleWithLabel("g1", "n", "v", "Enable feature", "with a help line", true, false)},
			{"Doughnut", c.DoughnutWithLabel(72, "CPU", "72%", 120)},
			{"Metric card", c.MetricCard("Requests", "1,204", "/s")},
			{"Login form", c.LoginForm(c.LoginFormData{Action: "/login", Error: "Invalid credentials", ShowWebAuthn: true})},
			{"Settings control", c.SettingsTextInput("name", "Display name", "Jane Doe", "shown in the header", "Dave")},
			{"Info tooltip", c.InfoTooltip("This explains the adjacent label.")},
		}
		for _, s := range sections {
			if err := section(s.title, s.body).Render(ctx, w); err != nil {
				return err
			}
		}
		writeStr(w, `</div></body></html>`)
		return nil
	})
}

func main() {
	staticFS, _ := fs.Sub(ui.StaticFiles, "static")
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticFS))))
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = page().Render(r.Context(), w)
	})
	addr := "127.0.0.1:8099"
	log.Printf("gallery on http://%s", addr)
	log.Fatal(http.ListenAndServe(addr, nil))
}
