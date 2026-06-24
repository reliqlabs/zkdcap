package circuit

import "github.com/consensys/gnark/frontend"

// In-circuit ASCII-hex parsing for deriving public outputs from
// signature-anchored bytes: the TCB-Info FMSPC is a 12-character uppercase-hex
// string, while the PCK leaf carries it as 6 raw DER bytes, so one side must be
// parsed to compare them.

// hexNibble decodes one ASCII hex character (0-9, A-F, a-f) to its 0..15 value,
// asserting the character is a valid hex digit. It uses one-hot equality (no
// range/sign tricks) so it is robust for any byte input.
func hexNibble(api frontend.API, x frontend.Variable) frontend.Variable {
	val := frontend.Variable(0)
	matched := frontend.Variable(0)
	// digits '0'-'9' -> 0..9
	for d := 0; d <= 9; d++ {
		is := api.IsZero(api.Sub(x, 0x30+d))
		val = api.Add(val, api.Mul(is, d))
		matched = api.Add(matched, is)
	}
	// 'A'-'F' / 'a'-'f' -> 10..15
	for d := 0; d <= 5; d++ {
		isU := api.IsZero(api.Sub(x, 0x41+d))
		isL := api.IsZero(api.Sub(x, 0x61+d))
		hit := api.Add(isU, isL)
		val = api.Add(val, api.Mul(hit, 10+d))
		matched = api.Add(matched, hit)
	}
	api.AssertIsEqual(matched, 1)
	return val
}

// hexBytesToBytes converts 2n ASCII hex characters (big-endian) to n byte
// values.
func hexBytesToBytes(api frontend.API, hexChars []frontend.Variable) []frontend.Variable {
	n := len(hexChars) / 2
	out := make([]frontend.Variable, n)
	for i := 0; i < n; i++ {
		hi := hexNibble(api, hexChars[2*i])
		lo := hexNibble(api, hexChars[2*i+1])
		out[i] = api.Add(api.Mul(hi, 16), lo)
	}
	return out
}

// isDecDigit returns (value, isDigit): value is the 0..9 digit value when x is
// an ASCII '0'-'9', and isDigit is 1 in that case, 0 otherwise. Unlike
// hexNibble it does not assert, so callers can parse a digit run terminated by
// a non-digit delimiter (',', '}', '"').
func isDecDigit(api frontend.API, x frontend.Variable) (val, isDigit frontend.Variable) {
	val = frontend.Variable(0)
	isDigit = frontend.Variable(0)
	for d := 0; d <= 9; d++ {
		is := api.IsZero(api.Sub(x, 0x30+d))
		val = api.Add(val, api.Mul(is, d))
		isDigit = api.Add(isDigit, is)
	}
	return val, isDigit
}

// parseDecimal parses an unsigned ASCII-decimal integer from chars[0:width].
// The value runs from chars[0] until the first non-digit (which terminates the
// JSON number, e.g. ',' or '}'), so it accepts 1..width digits. It asserts the
// first character is a digit (the field must be present) and that, once a
// non-digit terminator is seen, no further digit appears (no embedded garbage).
// The numeric values it parses (svn 0..255, pcesvn 0..65535, isvsvn 0..65535,
// isvprodid 0..65535) all fit within a few digits, so width is small.
func parseDecimal(api frontend.API, chars []frontend.Variable) frontend.Variable {
	acc := frontend.Variable(0)
	live := frontend.Variable(1) // 1 while still inside the leading digit run
	for i, ch := range chars {
		val, isDigit := isDecDigit(api, ch)
		if i == 0 {
			// The field value must start with a digit.
			api.AssertIsEqual(isDigit, 1)
		} else {
			// Once the run ended (live==0) a later digit is forbidden: this
			// rejects a non-canonical mix like "1,2" being read as the field.
			ended := api.Sub(1, live)
			api.AssertIsEqual(api.Mul(ended, isDigit), 0)
		}
		// Incorporate this char only if it is a digit AND we are still in the
		// run; otherwise freeze the accumulator. take = live AND isDigit.
		take := api.Mul(live, isDigit)
		acc = api.Select(take, api.Add(api.Mul(acc, 10), val), acc)
		live = take
	}
	return acc
}

// parseIso8601 parses a fixed-format ISO-8601 timestamp "YYYY-MM-DDThh:mm:ssZ"
// (the form Intel emits in TCB-Info / QE-Identity issueDate / nextUpdate) into a
// single order-preserving packed integer YYYYMMDDhhmmss. Because the format is
// fixed-width, lexicographic order on the packed integer equals chronological
// order, so a >= / <= comparison on the packed value is a valid date comparison.
// `s` must hold at least 20 characters (the literal length).
func parseIso8601(api frontend.API, s []frontend.Variable) frontend.Variable {
	// Digit positions inside "YYYY-MM-DDThh:mm:ssZ":
	//  0123 4 56 7 89 0 12 3 45 6 78 9
	//  YYYY - MM - DD T hh : mm : ss Z
	digitPos := []int{0, 1, 2, 3, 5, 6, 8, 9, 11, 12, 14, 15, 17, 18}
	acc := frontend.Variable(0)
	for _, p := range digitPos {
		val, isDigit := isDecDigit(api, s[p])
		api.AssertIsEqual(isDigit, 1) // each date position must be a decimal digit
		acc = api.Add(api.Mul(acc, 10), val)
	}
	return acc
}

// parseUtcTime parses a 13-character DER UTCTime "YYMMDDHHMMSSZ" (the form Intel
// emits in X.509 cert and CRL validity fields) into the same packed
// YYYYMMDDhhmmss integer as parseIso8601, assuming a 20xx century (Intel PKI is
// post-2000). The packed integer is order-preserving so a >= / <= comparison is
// a valid date comparison. `s` must hold at least 12 characters.
func parseUtcTime(api frontend.API, s []frontend.Variable) frontend.Variable {
	// "YYMMDDHHMMSSZ": all 12 leading chars are digits, trailing 'Z' ignored.
	acc := frontend.Variable(20) // century prefix => year 20YY
	for p := 0; p < 12; p++ {
		val, isDigit := isDecDigit(api, s[p])
		api.AssertIsEqual(isDigit, 1)
		acc = api.Add(api.Mul(acc, 10), val)
	}
	return acc
}
