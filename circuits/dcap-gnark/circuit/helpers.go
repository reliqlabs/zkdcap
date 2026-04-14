package circuit

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/sha2"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
)

// sha256Fixed computes SHA-256 over a fixed-length byte slice.
func sha256Fixed(api frontend.API, data []uints.U8) ([32]uints.U8, error) {
	h, err := sha2.New(api)
	if err != nil {
		return [32]uints.U8{}, err
	}
	h.Write(data)
	d := h.Sum()
	var out [32]uints.U8
	copy(out[:], d[:32])
	return out, nil
}

// sha256VarLen computes SHA-256 over the first `length` bytes of data.
func sha256VarLen(api frontend.API, data []uints.U8, length frontend.Variable) ([32]uints.U8, error) {
	h, err := sha2.New(api)
	if err != nil {
		return [32]uints.U8{}, err
	}
	h.Write(data)
	d := h.FixedLengthSum(length)
	var out [32]uints.U8
	copy(out[:], d[:32])
	return out, nil
}

// bytesToP256Fr converts a 32-byte SHA-256 digest to an emulated P256Fr element.
// The digest is big-endian (MSB first). FromBits expects LSB first.
func bytesToP256Fr(api frontend.API, digest [32]uints.U8) (*emulated.Element[P256Fr], error) {
	// Convert 32 bytes to 256 bits in little-endian order (LSB first)
	bits := make([]frontend.Variable, 256)
	for i := 0; i < 32; i++ {
		// Decompose byte to 8 bits (LSB first from ToBinary)
		byteVal := digest[31-i] // reverse byte order for LE bit layout
		byteBits := api.ToBinary(byteVal.Val, 8)
		for j := 0; j < 8; j++ {
			bits[i*8+j] = byteBits[j]
		}
	}

	f, err := emulated.NewField[P256Fr](api)
	if err != nil {
		return nil, err
	}
	return f.FromBits(bits...), nil
}

// assertBytesEqual asserts that two byte slices are equal element-by-element.
func assertBytesEqual(api frontend.API, a, b []uints.U8) error {
	bf, err := uints.NewBytes(api)
	if err != nil {
		return err
	}
	for i := range a {
		bf.AssertIsEqual(a[i], b[i])
	}
	return nil
}

// assertBytesEqualRange asserts a[aOff..aOff+n] == b[bOff..bOff+n].
func assertBytesEqualRange(api frontend.API, a []uints.U8, aOff int, b []uints.U8, bOff, n int) error {
	return assertBytesEqual(api, a[aOff:aOff+n], b[bOff:bOff+n])
}

// assertMaskedBytesEqual checks (a[i] & mask[i]) == (b[i] & mask[i]) for each byte.
func assertMaskedBytesEqual(api frontend.API, a, b, mask []uints.U8) error {
	bf, err := uints.NewBytes(api)
	if err != nil {
		return err
	}
	for i := range a {
		am := bf.And(a[i], mask[i])
		bm := bf.And(b[i], mask[i])
		bf.AssertIsEqual(am, bm)
	}
	return nil
}

// muxVar selects arr[idx] using a MUX. idx must be in [0, len(arr)).
func muxVar(api frontend.API, arr []frontend.Variable, idx frontend.Variable) frontend.Variable {
	n := len(arr)
	if n == 1 {
		return arr[0]
	}

	// result = sum(arr[i] * (i == idx))
	result := frontend.Variable(0)
	for i := 0; i < n; i++ {
		isI := api.IsZero(api.Sub(idx, i))
		result = api.Add(result, api.Mul(arr[i], isI))
	}
	return result
}

// assertGte asserts a >= b for frontend.Variable values (small values, <=32 bits).
func assertGte(api frontend.API, a, b frontend.Variable) {
	diff := api.Sub(a, b)
	api.ToBinary(diff, 32) // will fail if diff < 0 (underflow)
}

// maxVar returns max(a, b) for small frontend variables.
func maxVar(api frontend.API, a, b frontend.Variable) frontend.Variable {
	// Compute a - b. If a >= b, the high bit of the field element is 0.
	diff := api.Sub(a, b)
	bits := api.ToBinary(diff, 253)
	isNeg := bits[252] // high bit set means underflow (a < b)
	isGte := api.Sub(1, isNeg)
	return api.Select(isGte, a, b)
}

// u16FromLEBytes converts 2 little-endian uints.U8 to a frontend.Variable.
func u16FromLEBytes(api frontend.API, lo, hi uints.U8) frontend.Variable {
	return api.Add(lo.Val, api.Mul(hi.Val, 256))
}
