// journal builds the gnark witness for a quote+collateral and prints the public
// journal field-VALUES as JSON. Used by the cross-backend differential harness
// (.colosseum/diff-test-plan.md) to compare gnark's journal against the Noir
// circuit's decoded public inputs — partial-Z6 evidence for backend equivalence
// (intent 4.7) without needing a Groth16 setup.
//
//	go run ./cmd/journal -quote q.bin -collateral coll.json -timestamp 1750000000
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	"os"

	"github.com/consensys/gnark/std/math/uints"
	"github.com/reliqlabs/zkdcap/circuits/dcap-gnark/witness"
)

func main() {
	quotePath := flag.String("quote", "", "path to quote.bin")
	collPath := flag.String("collateral", "", "path to collateral.json")
	ts := flag.Uint64("timestamp", 1750000000, "verification time (unix seconds)")
	flag.Parse()
	if *quotePath == "" || *collPath == "" {
		fmt.Fprintln(os.Stderr, "need -quote and -collateral")
		os.Exit(2)
	}

	quoteBytes, err := os.ReadFile(*quotePath)
	must(err)
	collRaw, err := os.ReadFile(*collPath)
	must(err)
	var coll map[string]string
	must(json.Unmarshal(collRaw, &coll))

	c, err := witness.BuildWitness(quoteBytes, coll, *ts)
	must(err)

	j := map[string]any{
		"mr_td":             u8hex(c.MrTd[:]),
		"rtmr0":             u8hex(c.Rtmr0[:]),
		"rtmr1":             u8hex(c.Rtmr1[:]),
		"rtmr2":             u8hex(c.Rtmr2[:]),
		"rtmr3":             u8hex(c.Rtmr3[:]),
		"report_data":       u8hex(c.ReportData[:]),
		"cert_serial":       u8hex(c.CertSerial[:]),
		"fmspc":             u8hex(c.Fmspc[:]),
		"tcb_status":        vnum(c.TcbStatus),
		"timestamp":         vnum(c.Timestamp),
		"tcb_info_eval_num": vnum(c.TcbInfoEvalNum),
		"qe_id_eval_num":    vnum(c.QeIdEvalNum),
		"valid_from":        vnum(c.ValidFrom),
		"valid_until":       vnum(c.ValidUntil),
	}
	out, _ := json.MarshalIndent(j, "", "  ")
	fmt.Println(string(out))
}

// vnum extracts the integer value of a constant-assigned frontend.Variable by
// string-formatting it (robust across gnark's concrete constant types: int,
// uint*, *big.Int, field element). Returns it as a decimal string so large
// packed timestamps survive JSON without float rounding.
func vnum(v any) string {
	n, ok := new(big.Int).SetString(fmt.Sprintf("%v", v), 10)
	if !ok {
		panic(fmt.Sprintf("journal value not an integer: %v (%T)", v, v))
	}
	return n.String()
}

// u8hex renders a uints.U8 slice as a hex string by reading each byte's value.
func u8hex(b []uints.U8) string {
	out := make([]byte, len(b))
	for i := range b {
		n, ok := new(big.Int).SetString(fmt.Sprintf("%v", b[i].Val), 10)
		if !ok {
			panic(fmt.Sprintf("u8 value not an integer: %v", b[i].Val))
		}
		out[i] = byte(n.Uint64())
	}
	const hexdig = "0123456789abcdef"
	s := make([]byte, len(out)*2)
	for i, by := range out {
		s[i*2] = hexdig[by>>4]
		s[i*2+1] = hexdig[by&0x0f]
	}
	return string(s)
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "journal:", err)
		os.Exit(1)
	}
}
