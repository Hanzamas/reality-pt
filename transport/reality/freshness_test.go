package reality

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

// maxProfileLag is how many releases a profile may trail the browser before
// the check fails. Two releases is about two months.
const maxProfileLag = 2

// TestBrowserProfilesAreFresh compares the profiles that follow a browser with
// that browser's current stable release. A profile that trails the browser is
// a fingerprint of its own. It needs the network, so it only runs when
// REALITY_PT_FRESHNESS is set.
func TestBrowserProfilesAreFresh(t *testing.T) {
	if os.Getenv("REALITY_PT_FRESHNESS") == "" {
		t.Skip("set REALITY_PT_FRESHNESS=1 to compare with current browser releases")
	}

	t.Run("chrome", func(t *testing.T) {
		stable := chromeStableMajor(t)
		have := profileMajor(t, "chrome")
		t.Logf("Chrome stable is %d, the uTLS profile is %d", stable, have)
		if stable-have > maxProfileLag {
			t.Errorf("the chrome profile (%d) trails Chrome stable (%d) by more than %d releases", have, stable, maxProfileLag)
		}
	})
	t.Run("firefox", func(t *testing.T) {
		if _, err := lookupFingerprint("firefox"); err != nil {
			t.Skip("no firefox profile is registered")
		}
		stable := firefoxStableMajor(t)
		have := profileMajor(t, "firefox")
		t.Logf("Firefox stable is %d, the uTLS profile is %d", stable, have)
		if stable-have > maxProfileLag {
			t.Errorf("the firefox profile (%d) trails Firefox stable (%d) by more than %d releases", have, stable, maxProfileLag)
		}
	})
}

// profileMajor returns the browser major version of a profile.
func profileMajor(t *testing.T, name string) int {
	t.Helper()
	id, err := lookupFingerprint(name)
	if err != nil {
		t.Fatal(err)
	}
	major, err := strconv.Atoi(strings.SplitN(id.Version, "_", 2)[0])
	if err != nil {
		t.Fatalf("profile %q has version %q, not a number: %v", name, id.Version, err)
	}
	return major
}

func chromeStableMajor(t *testing.T) int {
	t.Helper()
	var releases []struct {
		Milestone int `json:"milestone"`
	}
	getJSON(t, "https://chromiumdash.appspot.com/fetch_releases?channel=Stable&platform=Windows&num=1", &releases)
	if len(releases) == 0 {
		t.Fatal("no Chrome stable release in the response")
	}
	return releases[0].Milestone
}

func firefoxStableMajor(t *testing.T) int {
	t.Helper()
	var versions struct {
		Latest string `json:"LATEST_FIREFOX_VERSION"`
	}
	getJSON(t, "https://product-details.mozilla.org/1.0/firefox_versions.json", &versions)
	major, err := strconv.Atoi(strings.SplitN(versions.Latest, ".", 2)[0])
	if err != nil {
		t.Fatalf("Firefox version %q is not a number: %v", versions.Latest, err)
	}
	return major
}

func getJSON(t *testing.T, url string, v any) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatal(fmt.Errorf("GET %s: %s", url, resp.Status))
	}
	if err := json.NewDecoder(resp.Body).Decode(v); err != nil {
		t.Fatalf("decode %s: %v", url, err)
	}
}
