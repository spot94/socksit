//go:build !preset

package preset

// embedded returns no preset in the default build.
func embedded() []byte { return nil }
