package frameio

import "testing"

func TestFile_IsFile(t *testing.T) {
	cases := []struct {
		t    string
		want bool
	}{
		{"file", true},
		{"folder", false},
		{"version_stack", false},
		{"", false},
	}
	for _, c := range cases {
		got := File{Type: c.t}.IsFile()
		if got != c.want {
			t.Errorf("type=%q: got %v want %v", c.t, got, c.want)
		}
	}
}

func TestFile_IsReady(t *testing.T) {
	cases := []struct {
		status string
		want   bool
	}{
		{"uploaded", true},
		{"transcoded", true},
		{"processed", true},
		{"ready", true},
		{"complete", true},
		{"done", true},
		{"created", false},
		{"uploading", false},
		{"", false},
		{"failed", false},
	}
	for _, c := range cases {
		got := File{Status: c.status}.IsReady()
		if got != c.want {
			t.Errorf("status=%q: got %v want %v", c.status, got, c.want)
		}
	}
}
