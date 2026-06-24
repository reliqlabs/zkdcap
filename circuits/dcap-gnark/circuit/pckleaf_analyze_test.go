package circuit

// Host-side layout analysis of the real Intel PCK leaf certificate, used to
// derive the fixed byte offsets (and the literal DER context preceding each
// field) that the in-circuit offset-assertion extraction (Step 2) relies on.
// Intel emits PCK leaf certs from a deterministic template, so these offsets
// are stable; the literal-context assertions in the circuit fail safe if a
// production cert ever deviates. Run:
//   go test ./circuit/ -run TestPckLeafLayout -v

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/asn1"
	"fmt"
	"testing"
)

var sgxExtOID = asn1.ObjectIdentifier{1, 2, 840, 113741, 1, 13, 1}
var fmspcOID = asn1.ObjectIdentifier{1, 2, 840, 113741, 1, 13, 1, 4}

// findFmspc walks the SGX extension SEQUENCE (a sequence of {OID, value}
// pairs) and returns the 6-byte FMSPC OCTET STRING value.
func findFmspc(t *testing.T, extValue []byte) []byte {
	t.Helper()
	var seq []asn1.RawValue
	if _, err := asn1.Unmarshal(extValue, &seq); err != nil {
		// extValue may itself be a single SEQUENCE; try unwrapping
		var outer asn1.RawValue
		if _, err2 := asn1.Unmarshal(extValue, &outer); err2 != nil {
			t.Fatalf("sgx ext parse: %v / %v", err, err2)
		}
		if _, err2 := asn1.Unmarshal(outer.Bytes, &seq); err2 != nil {
			t.Fatalf("sgx ext inner parse: %v", err2)
		}
	}
	for _, item := range seq {
		var pair struct {
			OID   asn1.ObjectIdentifier
			Value asn1.RawValue
		}
		if _, err := asn1.Unmarshal(item.FullBytes, &pair); err != nil {
			continue
		}
		if pair.OID.Equal(fmspcOID) {
			return pair.Value.Bytes
		}
	}
	t.Fatal("FMSPC not found in SGX extension")
	return nil
}

func TestPckLeafLayout(t *testing.T) {
	col := loadCollateral(t)
	chain := parsePEMChain(t, col["pck_certificate_chain"])
	leaf := chain[0]
	tbs := leaf.RawTBSCertificate
	t.Logf("PCK leaf TBS length: %d bytes", len(tbs))

	// --- serial ---
	ser := leaf.SerialNumber.Bytes()
	so := bytes.Index(tbs, ser)
	if so < 0 {
		t.Fatal("serial not found in TBS")
	}
	t.Logf("serial: %d bytes, offset %d, ctx[%d:%d]=%x value=%x", len(ser), so, so-4, so, tbs[so-4:so], ser)

	// --- subject public key (SEC1 uncompressed 04||X||Y, 65 bytes) ---
	pub := leaf.PublicKey.(*ecdsa.PublicKey)
	sec1 := make([]byte, 65)
	sec1[0] = 0x04
	pub.X.FillBytes(sec1[1:33])
	pub.Y.FillBytes(sec1[33:65])
	po := bytes.Index(tbs, sec1)
	if po < 0 {
		t.Fatal("subject pubkey not found in TBS")
	}
	t.Logf("subjectPubKey: 65 bytes, offset %d, ctx[%d:%d]=%x", po, po-8, po, tbs[po-8:po])

	// --- FMSPC (6 bytes) inside the SGX extension ---
	var fmspc []byte
	for _, ext := range leaf.Extensions {
		if ext.Id.Equal(sgxExtOID) {
			fmspc = findFmspc(t, ext.Value)
		}
	}
	if fmspc == nil {
		t.Fatal("SGX extension not found")
	}
	fo := bytes.Index(tbs, fmspc)
	if fo < 0 {
		t.Fatal("FMSPC not found in TBS")
	}
	t.Logf("FMSPC: %d bytes, offset %d, ctx[%d:%d]=%x value=%x", len(fmspc), fo, fo-14, fo, tbs[fo-14:fo], fmspc)

	// sanity: ensure no field overlaps the buffer cap we will declare
	t.Logf("max offset+len: serial=%d pubkey=%d fmspc=%d", so+len(ser), po+65, fo+len(fmspc))
}

// TestChainLayout reports the subject-pubkey offset/context per cert and the
// Intel SGX Root CA public key constants to pin in-circuit (the chain root).
func TestChainLayout(t *testing.T) {
	col := loadCollateral(t)
	chain := parsePEMChain(t, col["pck_certificate_chain"]) // leaf, platformCA, root
	names := []string{"leaf", "intermediate(PlatformCA)", "root(SGX Root CA)"}
	for i, c := range chain {
		tbs := c.RawTBSCertificate
		pub := c.PublicKey.(*ecdsa.PublicKey)
		sec1 := make([]byte, 65)
		sec1[0] = 0x04
		pub.X.FillBytes(sec1[1:33])
		pub.Y.FillBytes(sec1[33:65])
		po := bytes.Index(tbs, sec1)
		ctx := ""
		if po >= 8 {
			ctx = fmt.Sprintf("%x", tbs[po-8:po])
		}
		t.Logf("%-26s: TBS=%4d, subjPubKey off=%d ctx=%s", names[i], len(tbs), po, ctx)
	}
	root := chain[2].PublicKey.(*ecdsa.PublicKey)
	t.Logf("INTEL_SGX_ROOT_CA_X = %x", root.X.Bytes())
	t.Logf("INTEL_SGX_ROOT_CA_Y = %x", root.Y.Bytes())
}
