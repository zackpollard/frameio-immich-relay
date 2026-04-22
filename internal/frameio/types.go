package frameio

import "time"

// File is the subset of a Frame.io V4 file object we care about. Naming
// mirrors the V4 schema (see openapi.json). V4 splits "file" from "folder"
// as separate types rather than V2's polymorphic "asset".
type File struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Type       string     `json:"type"` // "file", "folder", "version_stack"
	Status     string     `json:"status"`
	FileSize   int64      `json:"file_size"`
	MediaType  string     `json:"media_type"`
	MediaLinks MediaLinks `json:"media_links"`
	ParentID   string     `json:"parent_id"`
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
}

// MediaLinks holds the pre-signed URLs V4 returns for downloading the
// original media and various renditions.
type MediaLinks struct {
	Original *MediaLink `json:"original,omitempty"`
}

// MediaLink is a pre-signed S3 URL pair for a single rendition.
type MediaLink struct {
	DownloadURL string `json:"download_url,omitempty"`
	InlineURL   string `json:"inline_url,omitempty"`
}

// IsFile reports whether this is a terminal file (not a folder / stack).
func (f File) IsFile() bool { return f.Type == "file" }

// Account is a V4 account — the top of the hierarchy.
type Account struct {
	ID          string `json:"id"`
	DisplayName string `json:"display_name"`
}

// Workspace lives inside an account and contains projects.
type Workspace struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// Project lives inside a workspace and points to a root folder where C2C
// uploads land.
type Project struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	RootFolderID string `json:"root_folder_id"`
}

// IsReady reports whether the file's bytes are actually downloadable.
// Observed progression on X-H2S C2C uploads:
//   - "created"    metadata row exists, bytes still uploading (S3 → 403)
//   - "uploaded"   bytes landed on S3 — downloadable, transcoding not yet done
//   - "transcoded" proxies generated too
//
// "uploaded" is the state the file is in right as file.upload.completed
// fires, so the webhook path relies on this being ready.
func (f File) IsReady() bool {
	switch f.Status {
	case "uploaded", "processed", "ready", "transcoded", "complete", "done":
		return true
	}
	return false
}
