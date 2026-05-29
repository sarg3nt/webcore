// Package migrate is a thin wrapper over golang-migrate that runs SQL
// migrations from a caller-supplied filesystem against a *sql.DB.
//
// Unlike the app-specific originals it was extracted from, this package does
// not embed any migration files itself — the consuming app owns its
// migrations and passes them in:
//
//	//go:embed migrations/*.sql
//	var migrationsFS embed.FS
//
//	r, err := migrate.New(db, migrationsFS, migrate.WithLogger(logger))
//	if err != nil { ... }
//	defer r.Close()
//	if err := r.Up(); err != nil { ... }
//
// The embedded files must follow golang-migrate's
// `NNN_name.up.sql` / `NNN_name.down.sql` naming. If the embed roots the files
// in a subdirectory, sub-root the FS before passing it in
// (fs.Sub(migrationsFS, "migrations")).
//
// The driver is SQLite (golang-migrate's sqlite driver, compatible with
// modernc.org/sqlite). The runner is built with NewWithInstance and therefore
// never closes the *sql.DB it was given — the caller owns the connection's
// lifecycle. Close() releases only the migration source.
package migrate

import (
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/sqlite"
	"github.com/golang-migrate/migrate/v4/source"
	"github.com/golang-migrate/migrate/v4/source/iofs"
)

// Runner applies migrations from a source filesystem to a database.
// It is not safe for concurrent use.
type Runner struct {
	m         *migrate.Migrate
	src       source.Driver
	logger    *slog.Logger
	autoForce bool
}

// Option configures a Runner.
type Option func(*Runner)

// WithLogger attaches a structured logger. Without it, the runner is silent.
func WithLogger(l *slog.Logger) Option {
	return func(r *Runner) { r.logger = l }
}

// WithAutoForceDirty makes Up() recover from a dirty migration state by
// forcing the recorded version clean before applying pending migrations.
// A dirty state means a prior migration failed partway; only enable this if
// your migrations are idempotent or you have verified the partial apply is
// safe to treat as complete.
func WithAutoForceDirty() Option {
	return func(r *Runner) { r.autoForce = true }
}

// New builds a Runner over db using the migrations in migrationsFS.
func New(db *sql.DB, migrationsFS fs.FS, opts ...Option) (*Runner, error) {
	r := &Runner{logger: slog.New(slog.DiscardHandler)}
	for _, opt := range opts {
		opt(r)
	}

	src, err := iofs.New(migrationsFS, ".")
	if err != nil {
		return nil, fmt.Errorf("iofs.New: %w", err)
	}
	drv, err := sqlite.WithInstance(db, &sqlite.Config{})
	if err != nil {
		return nil, fmt.Errorf("sqlite.WithInstance: %w", err)
	}
	m, err := migrate.NewWithInstance("iofs", src, "sqlite", drv)
	if err != nil {
		return nil, fmt.Errorf("migrate.NewWithInstance: %w", err)
	}
	r.m = m
	return r, nil
}

// Up applies all pending up-migrations. It is a no-op when already current and
// safe to call on every startup. With WithAutoForceDirty, a dirty state is
// forced clean before migrating.
func (r *Runner) Up() error {
	if r.autoForce {
		version, dirty, err := r.m.Version()
		if err != nil && !errors.Is(err, migrate.ErrNilVersion) {
			return fmt.Errorf("version: %w", err)
		}
		if dirty {
			r.logger.Warn("database in dirty migration state, forcing clean", "version", version)
			if err := r.m.Force(int(version)); err != nil {
				return fmt.Errorf("force clean: %w", err)
			}
		}
	}
	if err := r.m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("up: %w", err)
	}
	return nil
}

// Down rolls back all migrations. Destructive — intended for tests and
// teardown, not production startup.
func (r *Runner) Down() error {
	if err := r.m.Down(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("down: %w", err)
	}
	return nil
}

// Steps migrates n versions up (n > 0) or down (n < 0).
func (r *Runner) Steps(n int) error {
	if err := r.m.Steps(n); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("steps(%d): %w", n, err)
	}
	return nil
}

// Version reports the current migration version and whether the database is in
// a dirty (partially-applied) state. A fresh database reports (0, false, nil).
func (r *Runner) Version() (version uint, dirty bool, err error) {
	version, dirty, err = r.m.Version()
	if errors.Is(err, migrate.ErrNilVersion) {
		return 0, false, nil
	}
	return version, dirty, err
}

// Force sets the migration version and clears the dirty flag without running
// any migration. Use to recover from a known-good manual fix.
func (r *Runner) Force(version int) error {
	if err := r.m.Force(version); err != nil {
		return fmt.Errorf("force(%d): %w", version, err)
	}
	return nil
}

// Close releases the migration source driver. It does NOT close the database
// connection passed to New — the caller owns that.
func (r *Runner) Close() error {
	if r.src != nil {
		return r.src.Close()
	}
	return nil
}
