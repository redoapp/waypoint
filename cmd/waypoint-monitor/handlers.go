package main

import (
	"embed"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/redoapp/waypoint/internal/monitor"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static/*
var staticFS embed.FS

var funcMap = template.FuncMap{
	"formatBytes": formatBytes,
}

func formatBytes(b int64) string {
	const (
		KB = 1024
		MB = KB * 1024
		GB = MB * 1024
		TB = GB * 1024
	)
	switch {
	case b >= TB:
		return fmt.Sprintf("%.1f TB", float64(b)/float64(TB))
	case b >= GB:
		return fmt.Sprintf("%.1f GB", float64(b)/float64(GB))
	case b >= MB:
		return fmt.Sprintf("%.1f MB", float64(b)/float64(MB))
	case b >= KB:
		return fmt.Sprintf("%.1f KB", float64(b)/float64(KB))
	default:
		return fmt.Sprintf("%d B", b)
	}
}

type handlers struct {
	store  *monitor.Store
	tmpl   *template.Template
	logger *slog.Logger
}

func newHandlers(store *monitor.Store, logger *slog.Logger) (*handlers, error) {
	tmpl, err := template.New("").Funcs(funcMap).ParseFS(templateFS, "templates/*.html")
	if err != nil {
		return nil, fmt.Errorf("parse templates: %w", err)
	}
	return &handlers{store: store, tmpl: tmpl, logger: logger}, nil
}

func (h *handlers) registerRoutes(mux *http.ServeMux) {
	mux.Handle("GET /static/", http.FileServerFS(staticFS))
	mux.HandleFunc("GET /{$}", h.handleIndex)
	mux.HandleFunc("GET /partials/instances", h.handleInstances)
	mux.HandleFunc("GET /partials/users", h.handleUsers)
	mux.HandleFunc("DELETE /users/{user}/conns", h.handleResetConns)
	mux.HandleFunc("DELETE /users/{user}/bytes", h.handleResetBytes)
	mux.HandleFunc("DELETE /users/{user}/bandwidth/{period}", h.handleResetBandwidth)
	mux.HandleFunc("DELETE /users/{user}/all", h.handleResetAll)
}

func (h *handlers) handleIndex(w http.ResponseWriter, r *http.Request) {
	instances, err := h.store.DiscoverInstances(r.Context())
	if err != nil {
		h.logger.Error("discover instances", "error", err)
	}
	users, err := h.store.ListUsers(r.Context())
	if err != nil {
		h.logger.Error("list users", "error", err)
	}

	data := map[string]interface{}{
		"Instances": instances,
		"Users":     users,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.tmpl.ExecuteTemplate(w, "layout.html", data); err != nil {
		h.logger.Error("render layout", "error", err)
	}
}

func (h *handlers) handleInstances(w http.ResponseWriter, r *http.Request) {
	instances, err := h.store.DiscoverInstances(r.Context())
	if err != nil {
		h.logger.Error("discover instances", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.tmpl.ExecuteTemplate(w, "instances.html", instances); err != nil {
		h.logger.Error("render instances", "error", err)
	}
}

func (h *handlers) handleUsers(w http.ResponseWriter, r *http.Request) {
	users, err := h.store.ListUsers(r.Context())
	if err != nil {
		h.logger.Error("list users", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.tmpl.ExecuteTemplate(w, "users.html", users); err != nil {
		h.logger.Error("render users", "error", err)
	}
}

func (h *handlers) handleResetConns(w http.ResponseWriter, r *http.Request) {
	user := r.PathValue("user")
	if err := h.store.ResetConns(r.Context(), user); err != nil {
		h.logger.Error("reset conns", "user", user, "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	h.renderUserRow(w, r, user)
}

func (h *handlers) handleResetBytes(w http.ResponseWriter, r *http.Request) {
	user := r.PathValue("user")
	if err := h.store.ResetBytes(r.Context(), user); err != nil {
		h.logger.Error("reset bytes", "user", user, "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	h.renderUserRow(w, r, user)
}

func (h *handlers) handleResetBandwidth(w http.ResponseWriter, r *http.Request) {
	user := r.PathValue("user")
	periodStr := r.PathValue("period")
	periodSecs, err := strconv.ParseInt(periodStr, 10, 64)
	if err != nil {
		http.Error(w, "invalid period", http.StatusBadRequest)
		return
	}
	if err := h.store.ResetBandwidth(r.Context(), user, periodSecs); err != nil {
		h.logger.Error("reset bandwidth", "user", user, "period", periodSecs, "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	h.renderUserRow(w, r, user)
}

func (h *handlers) handleResetAll(w http.ResponseWriter, r *http.Request) {
	user := r.PathValue("user")
	if err := h.store.ResetAll(r.Context(), user); err != nil {
		h.logger.Error("reset all", "user", user, "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	h.renderUserRow(w, r, user)
}

func (h *handlers) renderUserRow(w http.ResponseWriter, r *http.Request, user string) {
	stats, err := h.store.GetUserStats(r.Context(), user)
	if err != nil {
		h.logger.Error("get user stats", "user", user, "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.tmpl.ExecuteTemplate(w, "user-row", stats); err != nil {
		h.logger.Error("render user row", "error", err)
	}
}
