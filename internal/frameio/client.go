package frameio

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// Client talks to the Frame.io V4 API using a TokenStore for auth.
type Client struct {
	Tokens    *TokenStore
	AccountID string // V4 scopes every endpoint under /accounts/{account_id}
	Base      string // default "https://api.frame.io/v4"
	HTTP      *http.Client
	OnLimit   func(remaining int) // optional, for logging
}

// NewClient builds a V4 client. AccountID is required — V4 nests every
// resource under /accounts/{account_id}.
func NewClient(tokens *TokenStore, accountID string) *Client {
	return &Client{
		Tokens:    tokens,
		AccountID: accountID,
		Base:      "https://api.frame.io/v4",
		HTTP:      &http.Client{Timeout: 5 * time.Minute},
	}
}

func (c *Client) do(ctx context.Context, method, path string, query url.Values, out any) (*http.Response, error) {
	access, err := c.Tokens.Valid(ctx, 60*time.Second)
	if err != nil {
		return nil, fmt.Errorf("frameio: token: %w", err)
	}
	u := c.Base + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+access)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("x-api-version", "v4")

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	if c.OnLimit != nil {
		if rem, perr := strconv.Atoi(resp.Header.Get("x-ratelimit-remaining")); perr == nil {
			c.OnLimit(rem)
		}
	}
	if resp.StatusCode >= 400 {
		defer resp.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
		return resp, fmt.Errorf("frameio: %s %s → %s: %s", method, path, resp.Status, string(body))
	}
	if out != nil {
		defer resp.Body.Close()
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			return resp, fmt.Errorf("frameio: decode %s: %w", path, err)
		}
	}
	return resp, nil
}

// AccountID helpers ----------------------------------------------------------

func (c *Client) accountPath(suffix string) string {
	return "/accounts/" + c.AccountID + suffix
}

// Me returns the authenticated user's display info — used as a sanity check.
func (c *Client) Me(ctx context.Context) (string, error) {
	var me struct {
		Data struct {
			ID    string `json:"id"`
			Name  string `json:"name"`
			Email string `json:"email"`
		} `json:"data"`
	}
	if _, err := c.do(ctx, "GET", "/me", nil, &me); err != nil {
		return "", err
	}
	if me.Data.Name != "" {
		return me.Data.Name, nil
	}
	return me.Data.Email, nil
}

// ListFolderChildren lists direct children (files + subfolders) of a folder.
// Pagination: follows `next_cursor` until exhausted.
func (c *Client) ListFolderChildren(ctx context.Context, folderID string) ([]File, error) {
	var out []File
	cursor := ""
	for {
		q := url.Values{}
		q.Set("page_size", "100")
		if cursor != "" {
			q.Set("after", cursor)
		}
		var page struct {
			Data []File `json:"data"`
			Meta struct {
				NextCursor string `json:"next_cursor"`
			} `json:"meta"`
		}
		_, err := c.do(ctx, "GET", c.accountPath("/folders/"+folderID+"/children"), q, &page)
		if err != nil {
			return nil, err
		}
		out = append(out, page.Data...)
		if page.Meta.NextCursor == "" {
			break
		}
		cursor = page.Meta.NextCursor
	}
	return out, nil
}

// GetFile refreshes a single file's metadata and requests the original
// download URL via include=media_links.original — V4 omits media_links
// by default ("drastically reduced default data") so this include is
// required to make the file downloadable.
func (c *Client) GetFile(ctx context.Context, fileID string) (File, error) {
	var wrap struct {
		Data File `json:"data"`
	}
	q := url.Values{"include": {"media_links.original"}}
	if _, err := c.do(ctx, "GET", c.accountPath("/files/"+fileID), q, &wrap); err != nil {
		return File{}, err
	}
	return wrap.Data, nil
}

// Download streams the original bytes of a file from its pre-signed URL.
func (c *Client) Download(ctx context.Context, f File) (io.ReadCloser, int64, error) {
	if f.MediaLinks.Original == nil || f.MediaLinks.Original.DownloadURL == "" {
		return nil, 0, fmt.Errorf("frameio: file %s has no original download_url", f.ID)
	}
	req, err := http.NewRequestWithContext(ctx, "GET", f.MediaLinks.Original.DownloadURL, nil)
	if err != nil {
		return nil, 0, err
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, 0, err
	}
	if resp.StatusCode >= 400 {
		defer resp.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		return nil, 0, fmt.Errorf("frameio: download %s → %s: %s", f.ID, resp.Status, string(body))
	}
	return resp.Body, resp.ContentLength, nil
}

// DeleteFile removes a file permanently.
func (c *Client) DeleteFile(ctx context.Context, fileID string) error {
	_, err := c.do(ctx, "DELETE", c.accountPath("/files/"+fileID), nil, nil)
	return err
}
