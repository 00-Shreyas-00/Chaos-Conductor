package repository

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// Querier is the subset of pgx used by the privilege check (satisfied by *pgxpool.Pool).
type Querier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// VerifyLeastPrivilege refuses to let the API run with a database role that could rewrite
// history or change the schema. It fails closed: any query error (including a missing
// audit table, i.e. migrations not applied) is a failure.
func VerifyLeastPrivilege(ctx context.Context, q Querier) error {
	var problems []error

	var super, createRole, createDB, bypassRLS, ownsDB bool
	err := q.QueryRow(ctx, `
		SELECT r.rolsuper, r.rolcreaterole, r.rolcreatedb, r.rolbypassrls,
		       pg_get_userbyid(d.datdba) = current_user
		FROM pg_roles r, pg_database d
		WHERE r.rolname = current_user AND d.datname = current_database()`).
		Scan(&super, &createRole, &createDB, &bypassRLS, &ownsDB)
	if err != nil {
		return fmt.Errorf("privilege check: read role attributes: %w", err)
	}
	if super || createRole || createDB || bypassRLS {
		problems = append(problems, errors.New("role has SUPERUSER/CREATEROLE/CREATEDB/BYPASSRLS"))
	}
	if ownsDB {
		problems = append(problems, errors.New("role owns the database (use the migrator role only for migrations)"))
	}

	for _, priv := range []string{"UPDATE", "DELETE", "TRUNCATE", "TRIGGER", "REFERENCES"} {
		var has bool
		if err := q.QueryRow(ctx, `SELECT has_table_privilege('audit.events', $1)`, priv).Scan(&has); err != nil {
			return fmt.Errorf("privilege check: audit.events (migrations applied?): %w", err)
		}
		if has {
			problems = append(problems, fmt.Errorf("role holds %s on audit.events", priv))
		}
	}
	for _, schema := range []string{"public", "app", "audit"} {
		var has bool
		if err := q.QueryRow(ctx, `SELECT has_schema_privilege($1, 'CREATE')`, schema).Scan(&has); err != nil {
			return fmt.Errorf("privilege check: schema %s: %w", schema, err)
		}
		if has {
			problems = append(problems, fmt.Errorf("role can CREATE in schema %s", schema))
		}
	}

	if len(problems) > 0 {
		return fmt.Errorf("database role is over-privileged; refusing to start: %w", errors.Join(problems...))
	}
	return nil
}
