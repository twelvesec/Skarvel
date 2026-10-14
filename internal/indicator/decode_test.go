package indicator

import "testing"

func TestDecodeCampaignIOC(t *testing.T) {
	got := Decode("aHR0cHM6Ly93d3cuaXByZWdpb25jaGVja2VyLm9yZy9hcGkvaXAtY2hlY2stZW5jcnlwdGVkLzNhZWIzNGEzMg==")
	want := "https://www.ipregionchecker.org/api/ip-check-encrypted/3aeb34a32"
	found := false
	for _, g := range got {
		if g == want {
			found = true
		}
		if !strictPrintable(g) {
			t.Errorf("non-printable decode %q", g)
		}
	}
	if !found {
		t.Fatalf("Decode = %q, want it to contain %q", got, want)
	}
}

func TestDecodeLeavesPlainIndicatorsAlone(t *testing.T) {
	for _, v := range []string{"codeprettier.pro", "172.86.126.227", "SuperStr0ngSecret@)@^", "3aeb34a32", "deadbeefcafe"} {
		if got := Decode(v); len(got) != 0 {
			t.Errorf("Decode(%q) = %q, want nothing", v, got)
		}
	}
}

func TestDecodeHex(t *testing.T) {
	got := Decode("636f646570726574746965722e70726f")
	if len(got) != 1 || got[0] != "codeprettier.pro" {
		t.Fatalf("Decode(hex) = %q", got)
	}
}
