package nftables

import "testing"

func TestParseVersionAndMinimum(t *testing.T) {
	version, err := ParseVersion("nftables v1.0.9 (Old Doc Yak)")
	if err != nil || version.String() != MinimumSupportedVersion || !version.AtLeast(minimumVersion()) {
		t.Fatalf("parse supported version: version=%s error=%v", version, err)
	}
	older, err := ParseVersion("nftables v1.0.8")
	if err != nil || older.AtLeast(minimumVersion()) {
		t.Fatalf("older version was accepted: version=%s error=%v", older, err)
	}
	if _, err := ParseVersion("nftables unknown"); err == nil {
		t.Fatalf("expected malformed version rejection")
	}
}
