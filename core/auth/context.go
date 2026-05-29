package auth

import "context"

type contextKey string

const userContextKey contextKey = "webcore.user"

// ContextWithUser returns a child context carrying the authenticated user.
// RequireAuth installs this; handlers read it via GetUserFromContext.
func ContextWithUser(ctx context.Context, user AuthUser) context.Context {
	return context.WithValue(ctx, userContextKey, user)
}

// GetUserFromContext retrieves the authenticated user installed by RequireAuth.
func GetUserFromContext(ctx context.Context) (AuthUser, bool) {
	user, ok := ctx.Value(userContextKey).(AuthUser)
	return user, ok
}
