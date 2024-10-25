package manifestclient

import (
	"context"
)

type ctxKey struct{}

var controllerNameCtxKey = ctxKey{}

func WithControllerNameInContext(ctx context.Context, name string) context.Context {
	return context.WithValue(ctx, controllerNameCtxKey, name)
}

func ControllerNameFromContext(ctx context.Context) string {
	val, _ := ctx.Value(controllerNameCtxKey).(string)
	return val
}
