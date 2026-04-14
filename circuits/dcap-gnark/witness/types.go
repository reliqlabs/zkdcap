package witness

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// PreVerifiedInputs is the host-side output of steps 1-3 (cert chain validation).
// This is the circuit-ready format with raw byte arrays.
type PreVerifiedInputs struct {
	TcbInfo    TcbInfo
	QeIdentity QeIdentityParsed
	PckLeafDer []byte
	CpuSvn     [16]byte
	PceSvn     uint16
	Fmspc      [6]byte
	Ppid       []byte
}

// TcbInfo contains the platform TCB information from Intel.
type TcbInfo struct {
	ID                      string     `json:"id"`
	Version                 uint8      `json:"version"`
	IssueDate               string     `json:"issueDate"`
	NextUpdate              string     `json:"nextUpdate"`
	Fmspc                   string     `json:"fmspc"`
	PceID                   string     `json:"pceId"`
	TcbType                 uint32     `json:"tcbType"`
	TcbEvaluationDataNumber uint32     `json:"tcbEvaluationDataNumber"`
	TcbLevels               []TcbLevel `json:"tcbLevels"`
}

// TcbLevel is a single TCB level entry.
type TcbLevel struct {
	Tcb         Tcb      `json:"tcb"`
	TcbDate     string   `json:"tcbDate"`
	TcbStatus   string   `json:"tcbStatus"`
	AdvisoryIDs []string `json:"advisoryIDs"`
}

// Tcb contains the component SVN values for a TCB level.
type Tcb struct {
	SgxComponents []TcbComponent `json:"sgxtcbcomponents"`
	TdxComponents []TcbComponent `json:"tdxtcbcomponents"`
	PceSvn        uint16         `json:"pcesvn"`
}

// TcbComponent is a single TCB component with an SVN value.
type TcbComponent struct {
	Svn uint8 `json:"svn"`
}

// QeIdentityJSON is the Intel JSON format (hex strings for byte fields).
type QeIdentityJSON struct {
	ID                      string       `json:"id"`
	Version                 uint8        `json:"version"`
	IssueDate               string       `json:"issueDate"`
	NextUpdate              string       `json:"nextUpdate"`
	TcbEvaluationDataNumber uint32       `json:"tcbEvaluationDataNumber"`
	MiscSelect              string       `json:"miscselect"`
	MiscSelectMask          string       `json:"miscselectMask"`
	Attributes              string       `json:"attributes"`
	AttributesMask          string       `json:"attributesMask"`
	MrSigner                string       `json:"mrsigner"`
	IsvProdID               uint16       `json:"isvprodid"`
	TcbLevels               []QeTcbLevel `json:"tcbLevels"`
}

// QeIdentityParsed has byte arrays ready for the circuit.
type QeIdentityParsed struct {
	MiscSelect     [4]byte
	MiscSelectMask [4]byte
	Attributes     [16]byte
	AttributesMask [16]byte
	MrSigner       [32]byte
	IsvProdID      uint16
	TcbLevels      []QeTcbLevel
}

// ParseQeIdentity converts Intel JSON format to parsed byte arrays.
func ParseQeIdentity(raw *QeIdentityJSON) (*QeIdentityParsed, error) {
	p := &QeIdentityParsed{
		IsvProdID: raw.IsvProdID,
		TcbLevels: raw.TcbLevels,
	}

	if err := hexToBytes(raw.MiscSelect, p.MiscSelect[:]); err != nil {
		return nil, fmt.Errorf("miscselect: %w", err)
	}
	if err := hexToBytes(raw.MiscSelectMask, p.MiscSelectMask[:]); err != nil {
		return nil, fmt.Errorf("miscselectMask: %w", err)
	}
	if err := hexToBytes(raw.Attributes, p.Attributes[:]); err != nil {
		return nil, fmt.Errorf("attributes: %w", err)
	}
	if err := hexToBytes(raw.AttributesMask, p.AttributesMask[:]); err != nil {
		return nil, fmt.Errorf("attributesMask: %w", err)
	}
	if err := hexToBytes(raw.MrSigner, p.MrSigner[:]); err != nil {
		return nil, fmt.Errorf("mrsigner: %w", err)
	}

	return p, nil
}

func hexToBytes(s string, dst []byte) error {
	b, err := hex.DecodeString(s)
	if err != nil {
		return err
	}
	if len(b) != len(dst) {
		return fmt.Errorf("expected %d bytes, got %d", len(dst), len(b))
	}
	copy(dst, b)
	return nil
}

// QeTcbLevel is a QE identity TCB level entry.
type QeTcbLevel struct {
	Tcb         QeTcb    `json:"tcb"`
	TcbDate     string   `json:"tcbDate"`
	TcbStatus   string   `json:"tcbStatus"`
	AdvisoryIDs []string `json:"advisoryIDs"`
}

// QeTcb contains the isv_svn threshold for a QE TCB level.
type QeTcb struct {
	IsvSvn uint16 `json:"isvsvn"`
}

// TcbStatus severity encoding (matches circuit constants).
var TcbStatusSeverity = map[string]int{
	"UpToDate":                          0,
	"SWHardeningNeeded":                 1,
	"ConfigurationNeeded":               2,
	"ConfigurationAndSWHardeningNeeded": 3,
	"OutOfDate":                         4,
	"OutOfDateConfigurationNeeded":      5,
	"Revoked":                           6,
}

// PreVerifiedJSON is the JSON-serializable format for PreVerifiedInputs.
type PreVerifiedJSON struct {
	TcbInfo    TcbInfo          `json:"tcb_info"`
	QeIdentity QeIdentityJSON   `json:"qe_identity"`
	PckLeafDer HexBytes         `json:"pck_leaf_der"`
	CpuSvn     HexFixedBytes16  `json:"cpu_svn"`
	PceSvn     uint16           `json:"pce_svn"`
	Fmspc      HexFixedBytes6   `json:"fmspc"`
	Ppid       HexBytes         `json:"ppid"`
}

// HexBytes is a JSON-serializable byte slice (hex encoded).
type HexBytes []byte

func (h HexBytes) MarshalJSON() ([]byte, error) {
	return json.Marshal(hex.EncodeToString(h))
}

func (h *HexBytes) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return err
	}
	*h = b
	return nil
}

// HexFixedBytes16 is a [16]byte that serializes as hex.
type HexFixedBytes16 [16]byte

func (h HexFixedBytes16) MarshalJSON() ([]byte, error) {
	return json.Marshal(hex.EncodeToString(h[:]))
}

func (h *HexFixedBytes16) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return err
	}
	copy(h[:], b)
	return nil
}

// HexFixedBytes6 is a [6]byte that serializes as hex.
type HexFixedBytes6 [6]byte

func (h HexFixedBytes6) MarshalJSON() ([]byte, error) {
	return json.Marshal(hex.EncodeToString(h[:]))
}

func (h *HexFixedBytes6) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return err
	}
	copy(h[:], b)
	return nil
}

// ToPreVerifiedInputs converts the JSON-serializable format to the circuit-ready format.
func (p *PreVerifiedJSON) ToPreVerifiedInputs() (*PreVerifiedInputs, error) {
	qe, err := ParseQeIdentity(&p.QeIdentity)
	if err != nil {
		return nil, fmt.Errorf("parsing QE identity: %w", err)
	}

	return &PreVerifiedInputs{
		TcbInfo:    p.TcbInfo,
		QeIdentity: *qe,
		PckLeafDer: []byte(p.PckLeafDer),
		CpuSvn:     [16]byte(p.CpuSvn),
		PceSvn:     p.PceSvn,
		Fmspc:      [6]byte(p.Fmspc),
		Ppid:       []byte(p.Ppid),
	}, nil
}
