package plugins

// Version is this module's release tag. Unlike crs/v4, coraza/v3, and lts/v4
// (whose Version tracks an upstream tag), the plugins bundle aggregates
// multiple upstream plugins with independent versions, so Version reflects
// the version of this bundle itself.
//
// Bumped manually by maintainers when cutting a new plugins/vX.Y.Z tag.
// Individual plugin upstream versions live in plugins/versions.json.
const Version = "v0.1.0"
