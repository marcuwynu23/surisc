# Release Notes

## Version

{{ .Version }}

## Release Date

{{ .ReleaseDate }}

---

{{ range .Sections }}{{ if .Commits }}
## {{ .Title }}

{{ range .Commits }}
- {{ .Header }}{{ end }}
{{ end }}{{ end }}

{{ if .Contributors }}
## Contributors

{{ range .Contributors }}
- {{ .Name }} ({{ .Count }} commits)
{{ end }}{{ end }}
