package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	//setup
	fakeHeader := http.Header{}
	//test no authorization header included
	got, goterr := GetAPIKey(fakeHeader)
	want := ""
	wanterr := ErrNoAuthHeaderIncluded
	if got != want || goterr != wanterr {
		t.Fatalf("GetAPIKey with no auth: got: %q, %q; want: %q, %q", got, goterr, want, wanterr)
	}
	//test malformed authorization header (missing ApiKey)
	fakeHeader = http.Header{
		"Authorization": []string{""},
	}
	got, goterr = GetAPIKey(fakeHeader)
	want = ""
	wanterr = errors.New("no authorization header included")
	if got != want || goterr.Error() != wanterr.Error() {
		t.Fatalf("GetAPIKey with malformed auth: got: %q, %q; want: %q, %q", got, goterr, want, wanterr)
	}

	//test malformed authorization header (missing ApiKey value)
	fakeHeader = http.Header{
		"Authorization": []string{"ApiKey"},
	}
	got, goterr = GetAPIKey(fakeHeader)
	want = ""
	wanterr = errors.New("malformed authorization header")
	if got != want || goterr.Error() != wanterr.Error() {
		t.Fatalf("GetAPIKey with malformed auth: got: %q, %q; want: %q, %q", got, goterr, want, wanterr)
	}
	//test valid authorization header
	fakeHeader = http.Header{
		"Authorization": []string{"ApiKey value"},
	}
	got, goterr = GetAPIKey(fakeHeader)
	want = "value"
	wanterr = nil
	if got != want || goterr != wanterr {
		t.Fatalf("GetAPIKey with valid auth: got: %q, %q; want: %q, %q", got, goterr, want, wanterr)
	}
}
