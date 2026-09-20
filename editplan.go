package urn

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

// ComponentName identifies a URN component addressable by an EditPlan.
type ComponentName string

const (
	ComponentNID      ComponentName = "nid"
	ComponentNSS      ComponentName = "nss"
	ComponentR        ComponentName = "r-component"
	ComponentQ        ComponentName = "q-component"
	ComponentFragment ComponentName = "fragment"
)

// EditOption describes a single component edit when building an EditPlan.
type EditOption func() (ComponentName, editOp, error)

// ReplaceNID replaces the namespace identifier.
func ReplaceNID(value string) EditOption {
	return func() (ComponentName, editOp, error) {
		return ComponentNID, editOp{intent: editReplace, value: value}, nil
	}
}

// ReplaceNSS replaces the namespace-specific string.
func ReplaceNSS(value string) EditOption {
	return func() (ComponentName, editOp, error) {
		return ComponentNSS, editOp{intent: editReplace, value: value}, nil
	}
}

// ReplaceRComponent replaces the r-component (RFC 8141 only).
func ReplaceRComponent(value string) EditOption {
	return func() (ComponentName, editOp, error) {
		return ComponentR, editOp{intent: editReplace, value: value}, nil
	}
}

// ReplaceQComponent replaces the q-component (RFC 8141 only).
func ReplaceQComponent(value string) EditOption {
	return func() (ComponentName, editOp, error) {
		return ComponentQ, editOp{intent: editReplace, value: value}, nil
	}
}

// ReplaceFragment replaces the fragment component (RFC 8141 only).
func ReplaceFragment(value string) EditOption {
	return func() (ComponentName, editOp, error) {
		return ComponentFragment, editOp{intent: editReplace, value: value}, nil
	}
}

// DeleteRComponent removes the r-component and its "?+" separator.
func DeleteRComponent() EditOption {
	return func() (ComponentName, editOp, error) {
		return ComponentR, editOp{intent: editDelete}, nil
	}
}

// DeleteQComponent removes the q-component and its "?=" separator.
func DeleteQComponent() EditOption {
	return func() (ComponentName, editOp, error) {
		return ComponentQ, editOp{intent: editDelete}, nil
	}
}

// DeleteFragment removes the fragment component and its "#" separator.
func DeleteFragment() EditOption {
	return func() (ComponentName, editOp, error) {
		return ComponentFragment, editOp{intent: editDelete}, nil
	}
}

type editIntent int

const (
	editReplace editIntent = iota + 1
	editDelete
)

type editOp struct {
	intent editIntent
	value  string
}

// Conflict records a component both sides of a merge, or a plan and the
// latest value during a rebase, modified independently.
type Conflict struct {
	Component ComponentName
	Base      string
	Left      string
	LeftOp    ConflictOp
	Right     string
	RightOp   ConflictOp
}

// ConflictOp describes what one side of a conflict did to a component.
type ConflictOp int

const (
	OpReplaced ConflictOp = iota
	OpDeleted
)

func (op ConflictOp) String() string {
	switch op {
	case OpDeleted:
		return "deleted"
	default:
		return "replaced"
	}
}

// MergeError reports every component conflict found during a merge or rebase.
type MergeError struct {
	Conflicts []Conflict
}

func (e *MergeError) Error() string {
	names := make([]string, len(e.Conflicts))
	for i, c := range e.Conflicts {
		names[i] = string(c.Component)
	}
	return fmt.Sprintf("edit plan conflicts on components: %s", strings.Join(names, ", "))
}

// ErrPlanHasConflicts is returned when applying a plan that still carries conflicts.
var ErrPlanHasConflicts = errors.New("edit plan has unresolved conflicts")

// EditPlan is an immutable description of changes to make to a parsed URN.
//
// It remembers the exact original text the plan was created from, the parsing
// mode used to parse it, and a stable fingerprint binding the two.
// Plans can be marshaled to and unmarshaled from JSON, merged with other plans
// built on the same baseline, and rebased onto a newer value of the URN.
type EditPlan struct {
	// original is the exact text the plan was created from. It never changes,
	// even after a rebase, and is the reference for component diffs.
	original string
	// baseline is the text edits are assembled onto. It equals original until
	// a successful rebase moves the plan onto a newer URN value.
	baseline    string
	mode        ParsingMode
	fingerprint string
	edits       map[ComponentName]editOp
	// owned reports which edits were authored on this plan rather than carried
	// in from a newer URN value during a rebase.
	owned     map[ComponentName]bool
	conflicts []Conflict
}

// NewEditPlan creates an edit plan from a parsed URN.
//
// The URN must have been produced by the parser. Replacement literals are
// validated against the component syntax of the parsing mode the URN was
// parsed with; components exclusive to RFC 8141 are rejected for RFC 2141
// and SCIM URNs. Duplicate intents for the same component are rejected.
func NewEditPlan(u *URN, opts ...EditOption) (*EditPlan, error) {
	if u == nil {
		return nil, errors.New("cannot create an edit plan from a nil URN")
	}
	mode, err := modeForKind(u.kind)
	if err != nil {
		return nil, err
	}
	original := u.String()
	if original == "" {
		return nil, errors.New("cannot create an edit plan from an incomplete URN")
	}
	parsed, ok := Parse([]byte(original), WithParsingMode(mode))
	if !ok || parsed == nil || parsed.String() != original {
		return nil, fmt.Errorf("edit plan baseline is not a reproducible URN: %s", original)
	}

	edits := make(map[ComponentName]editOp, len(opts))
	for _, opt := range opts {
		component, op, optErr := opt()
		if optErr != nil {
			return nil, optErr
		}
		if _, exists := edits[component]; exists {
			return nil, fmt.Errorf("duplicate edit intent for component %q", component)
		}
		if err := validateEdit(mode, component, op); err != nil {
			return nil, err
		}
		edits[component] = op
	}

	owned := make(map[ComponentName]bool, len(edits))
	for component := range edits {
		owned[component] = true
	}
	return &EditPlan{
		original:    original,
		baseline:    original,
		mode:        mode,
		fingerprint: fingerprintFor(mode, original),
		edits:       edits,
		owned:       owned,
	}, nil
}

// OriginalText returns the exact, byte-for-byte text the plan was created from.
//
// It is immutable and is the reference against which component diffs are computed.
func (p *EditPlan) OriginalText() string { return p.original }

// BaselineText returns the text edits are assembled onto.
//
// It equals OriginalText until the plan is rebased onto a newer URN value.
func (p *EditPlan) BaselineText() string { return p.baseline }

// Mode returns the parsing mode recorded at creation time.
func (p *EditPlan) Mode() ParsingMode { return p.mode }

// Fingerprint returns the stable fingerprint binding the original text to its parsing mode.
func (p *EditPlan) Fingerprint() string { return p.fingerprint }

// Conflicts returns the conflicts recorded on the plan after a merge or rebase.
func (p *EditPlan) Conflicts() []Conflict {
	if len(p.conflicts) == 0 {
		return nil
	}
	out := make([]Conflict, len(p.conflicts))
	copy(out, p.conflicts)
	return out
}

func modeForKind(k Kind) (ParsingMode, error) {
	switch k {
	case RFC2141:
		return RFC2141Only, nil
	case RFC7643:
		return RFC7643Only, nil
	case RFC8141:
		return RFC8141Only, nil
	default:
		return Default, errors.New("edit plans require a URN produced by the parser")
	}
}

func fingerprintFor(mode ParsingMode, original string) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("%d\n%s", mode, original)))
	return hex.EncodeToString(h[:])
}

// conflictsDigest binds the recorded conflicts (and the edits that back them)
// to the baseline fingerprint, so tampering with conflict fields after
// marshaling is detected on unmarshal.
func conflictsDigest(fingerprint string, edits []componentEditDTO, conflicts []conflictDTO) string {
	if len(conflicts) == 0 {
		return ""
	}
	mac := hmac.New(sha256.New, []byte(fingerprint))
	enc := json.NewEncoder(mac)
	_ = enc.Encode(edits)
	_ = enc.Encode(conflicts)
	return hex.EncodeToString(mac.Sum(nil))
}

// componentOrder defines a deterministic order for diffs, merges and JSON.
var componentOrder = []ComponentName{ComponentNID, ComponentNSS, ComponentR, ComponentQ, ComponentFragment}

// modeComponents reports which components are addressable in a given mode.
func modeAllowsComponent(mode ParsingMode, c ComponentName) bool {
	switch mode {
	case RFC8141Only:
		return true
	case RFC2141Only, RFC7643Only:
		return c == ComponentNID || c == ComponentNSS
	default:
		return false
	}
}

func validateEdit(mode ParsingMode, c ComponentName, op editOp) error {
	if !modeAllowsComponent(mode, c) {
		return fmt.Errorf("component %q is not supported in parsing mode %d", c, mode)
	}
	if op.intent == editDelete {
		if c == ComponentNID || c == ComponentNSS {
			return fmt.Errorf("component %q cannot be deleted", c)
		}
		return nil
	}
	if op.intent != editReplace {
		return fmt.Errorf("unknown edit intent for component %q", c)
	}
	if op.value == "" {
		return fmt.Errorf("replacement value for component %q must not be empty", c)
	}
	if err := validateLiteral(c, op.value); err != nil {
		return fmt.Errorf("invalid replacement for component %q: %w", c, err)
	}
	if err := validateAgainstGrammar(mode, c, op.value); err != nil {
		return fmt.Errorf("invalid replacement for component %q: %w", c, err)
	}
	return nil
}

// validateLiteral enforces byte-level rules the state machine is lenient about
// and that the task requires strictly for replacement values:
// no raw (non-ASCII) Unicode, and every percent-escape must be complete with
// exactly two hexadecimal digits.
func validateLiteral(c ComponentName, value string) error {
	for i := 0; i < len(value); i++ {
		b := value[i]
		if b >= 0x80 {
			return fmt.Errorf("raw non-ASCII byte at position %d", i)
		}
		if b == '%' {
			if i+2 >= len(value) || !isHexDigit(value[i+1]) || !isHexDigit(value[i+2]) {
				return fmt.Errorf("incomplete or malformed percent-escape at position %d", i)
			}
			i += 2
		}
	}
	return nil
}

func isHexDigit(b byte) bool {
	return ('0' <= b && b <= '9') || ('a' <= b && b <= 'f') || ('A' <= b && b <= 'F')
}

// validateAgainstGrammar builds a full probe URN using the replacement literal
// and reparses it with the recorded mode, then verifies the state machine
// extracted exactly the submitted literal. This rejects values that contain
// unencoded separator content (?, #) or otherwise violate component syntax.
func validateAgainstGrammar(mode ParsingMode, c ComponentName, value string) error {
	var probe string
	switch mode {
	case RFC2141Only:
		switch c {
		case ComponentNID:
			probe = "urn:" + value + ":nss"
		case ComponentNSS:
			probe = "urn:nid:" + value
		}
	case RFC7643Only:
		switch c {
		case ComponentNID:
			probe = "urn:" + value + ":schemas:core"
		case ComponentNSS:
			probe = "urn:ietf:params:scim:" + value
		}
	case RFC8141Only:
		switch c {
		case ComponentNID:
			probe = "urn:" + value + ":nss"
		case ComponentNSS:
			probe = "urn:nid:" + value
		case ComponentR:
			probe = "urn:nid:nss?+" + value
		case ComponentQ:
			probe = "urn:nid:nss?=" + value
		case ComponentFragment:
			probe = "urn:nid:nss#" + value
		}
	default:
		return fmt.Errorf("unknown parsing mode %d", mode)
	}

	parsed, ok := Parse([]byte(probe), WithParsingMode(mode))
	if !ok || parsed == nil {
		return fmt.Errorf("literal is not valid per parsing mode %d", mode)
	}
	got := componentOf(parsed, c)
	if mode == RFC7643Only && c == ComponentNID {
		got = parsed.ID
	}
	if got != value {
		return fmt.Errorf("literal contains unencoded component separators or does not occupy the whole component")
	}
	// Reassembling the probe must be byte-identical: an unencoded separator
	// that silently terminated the component (e.g. an empty trailing fragment)
	// is rejected.
	if parsed.String() != probe {
		return fmt.Errorf("literal does not survive a parse-edit-string round-trip")
	}
	return nil
}

func componentOf(u *URN, c ComponentName) string {
	switch c {
	case ComponentNID:
		return u.ID
	case ComponentNSS:
		return u.SS
	case ComponentR:
		return u.rComponent
	case ComponentQ:
		return u.qComponent
	case ComponentFragment:
		return u.fComponent
	default:
		return ""
	}
}

// assemble constructs the full candidate text for a plan.
//
// Fragments that are not edited are copied verbatim from the baseline,
// preserving prefix casing, percent-escape letter casing, and the separators
// of already-present non-empty optional components.
func assemble(u *URN, edits map[ComponentName]editOp) string {
	prefix := u.prefix
	if prefix == "" {
		prefix = "urn"
	}
	id := u.ID
	ss := u.SS
	r := u.rComponent
	q := u.qComponent
	f := u.fComponent

	if op, ok := edits[ComponentNID]; ok {
		id = op.value
	}
	if op, ok := edits[ComponentNSS]; ok {
		ss = op.value
	}
	if op, ok := edits[ComponentR]; ok {
		if op.intent == editDelete {
			r = ""
		} else {
			r = op.value
		}
	}
	if op, ok := edits[ComponentQ]; ok {
		if op.intent == editDelete {
			q = ""
		} else {
			q = op.value
		}
	}
	if op, ok := edits[ComponentFragment]; ok {
		if op.intent == editDelete {
			f = ""
		} else {
			f = op.value
		}
	}

	res := prefix + ":" + id + ":" + ss
	if r != "" {
		res += "?+" + r
	}
	if q != "" {
		res += "?=" + q
	}
	if f != "" {
		res += "#" + f
	}
	return res
}

// ComponentChange describes the old and new literal value of one component.
//
// Added components have an empty Old value; removed components have an empty New value.
type ComponentChange struct {
	Old     string
	New     string
	Deleted bool
	Added   bool
}

// ComponentDiff lists every component changed by applying a plan.
type ComponentDiff struct {
	Changes map[ComponentName]ComponentChange
}

// Apply constructs the full candidate URN text, reparses it with the original
// parsing mode, and verifies the result before returning a new URN and its
// component-level diff.
//
// On failure the baseline URN is untouched and no half-applied state is kept.
// Plans that still contain conflicts cannot be applied.
func (p *EditPlan) Apply() (*URN, *ComponentDiff, error) {
	if len(p.conflicts) > 0 {
		return nil, nil, ErrPlanHasConflicts
	}

	if fingerprintFor(p.mode, p.baseline) != p.fingerprint {
		return nil, nil, errors.New("edit plan fingerprint does not match its baseline")
	}
	base, ok := Parse([]byte(p.baseline), WithParsingMode(p.mode))
	if !ok || base == nil {
		return nil, nil, fmt.Errorf("baseline URN is no longer parseable in mode %d", p.mode)
	}
	origin, ok := Parse([]byte(p.original), WithParsingMode(p.mode))
	if !ok || origin == nil {
		return nil, nil, fmt.Errorf("original URN is no longer parseable in mode %d", p.mode)
	}

	candidate := assemble(base, p.edits)
	updated, parseOK := Parse([]byte(candidate), WithParsingMode(p.mode))
	if !parseOK || updated == nil {
		return nil, nil, fmt.Errorf("resulting URN is invalid per parsing mode %d: %s", p.mode, candidate)
	}
	if updated.String() != candidate {
		return nil, nil, fmt.Errorf("resulting URN did not survive parse-edit-string round-trip: %s", candidate)
	}
	for c, op := range p.edits {
		want := ""
		if op.intent == editReplace {
			want = op.value
		}
		if got := componentOf(updated, c); got != want {
			return nil, nil, fmt.Errorf("component %q of resulting URN is %q, expected %q", c, got, want)
		}
	}

	return updated, diffFor(origin, updated), nil
}

func diffFor(origin, updated *URN) *ComponentDiff {
	changes := make(map[ComponentName]ComponentChange)
	for _, c := range componentOrder {
		old := componentOf(origin, c)
		new := componentOf(updated, c)
		if old == new {
			continue
		}
		changes[c] = ComponentChange{
			Old:     old,
			New:     new,
			Deleted: old != "" && new == "",
			Added:   old == "" && new != "",
		}
	}
	return &ComponentDiff{Changes: changes}
}

// Merge combines two plans built on the same baseline.
//
// Edits to different components are combined, producing the same result
// regardless of merge order. Edits to the same component on both sides are
// reported as conflicts (all of them at once); equivalent replacement
// literals are still conflicts, and so are replace/delete pairs.
// Matching delete intents on both sides combine into a single delete.
//
// The returned plan holds the conflicts and cannot be applied until resolved.
func (p *EditPlan) Merge(other *EditPlan) (*EditPlan, error) {
	if other == nil {
		return nil, errors.New("cannot merge with a nil plan")
	}
	if p.mode != other.mode {
		return nil, fmt.Errorf("parsing mode mismatch: %d vs %d", p.mode, other.mode)
	}
	if p.baseline != other.baseline || p.fingerprint != other.fingerprint {
		return nil, errors.New("edit plans were created from different baselines")
	}

	base, ok := Parse([]byte(p.baseline), WithParsingMode(p.mode))
	if !ok || base == nil {
		return nil, errors.New("baseline URN is no longer parseable")
	}

	merged := &EditPlan{
		original:    p.original,
		baseline:    p.baseline,
		mode:        p.mode,
		fingerprint: p.fingerprint,
		edits:       make(map[ComponentName]editOp),
		owned:       make(map[ComponentName]bool),
	}

	var conflicts []Conflict
	for _, c := range componentOrder {
		lop, lTouched := p.edits[c]
		rop, rTouched := other.edits[c]
		lOwned := p.owned[c]
		rOwned := other.owned[c]
		switch {
		case lTouched && !rTouched:
			merged.edits[c] = lop
			merged.owned[c] = lOwned
		case rTouched && !lTouched:
			merged.edits[c] = rop
			merged.owned[c] = rOwned
		case lTouched && rTouched:
			merged.owned[c] = lOwned || rOwned
			switch {
			case !lOwned && !rOwned:
				// Both sides merely carried the same upstream value.
				merged.edits[c] = lop
			case lOwned != rOwned:
				// One side authored the change, the other only carried it.
				if lOwned {
					merged.edits[c] = lop
				} else {
					merged.edits[c] = rop
				}
			case lop.intent == editDelete && rop.intent == editDelete:
				// Two identical delete intents converge.
				merged.edits[c] = lop
			default:
				// Both sides authored a change: visible conflict, even when
				// the candidate literals normalize to the same value. The
				// left edit is retained so the plan keeps a concrete
				// (though non-applicable) candidate.
				merged.edits[c] = lop
				conflicts = append(conflicts, Conflict{
					Component: c,
					Base:      componentOf(base, c),
					Left:      conflictLiteral(lop),
					LeftOp:    conflictOp(lop),
					Right:     conflictLiteral(rop),
					RightOp:   conflictOp(rop),
				})
			}
		}
	}

	// A plan produced by a merge retains previously recorded conflicts as well.
	conflicts = append(conflicts, p.conflicts...)
	conflicts = append(conflicts, other.conflicts...)

	merged.conflicts = conflicts
	if len(conflicts) > 0 {
		return merged, &MergeError{Conflicts: conflicts}
	}
	return merged, nil
}

func conflictLiteral(op editOp) string {
	if op.intent == editReplace {
		return op.value
	}
	return ""
}

func conflictOp(op editOp) ConflictOp {
	if op.intent == editDelete {
		return OpDeleted
	}
	return OpReplaced
}

// Rebase re-applies the plan onto a newer URN value.
//
// Components changed only by the latest value are carried into the rebased
// plan automatically. Components changed by both the plan and the latest
// value are reported as component-level conflicts, even when the resulting
// URNs would be lexically equivalent.
func (p *EditPlan) Rebase(latest *URN) (*EditPlan, error) {
	if len(p.conflicts) > 0 {
		return nil, ErrPlanHasConflicts
	}
	if latest == nil {
		return nil, errors.New("cannot rebase onto a nil URN")
	}
	latestMode, err := modeForKind(latest.kind)
	if err != nil {
		return nil, err
	}
	if latestMode != p.mode {
		return nil, fmt.Errorf("parsing mode mismatch: %d vs %d", p.mode, latestMode)
	}

	origin, ok := Parse([]byte(p.original), WithParsingMode(p.mode))
	if !ok || origin == nil {
		return nil, errors.New("original URN is no longer parseable")
	}
	latestText := latest.String()
	latestParsed, ok := Parse([]byte(latestText), WithParsingMode(p.mode))
	if !ok || latestParsed == nil || latestParsed.String() != latestText {
		return nil, errors.New("latest value is not a reproducible URN in the plan's parsing mode")
	}

	rebased := &EditPlan{
		original:    p.original,
		baseline:    latestText,
		mode:        p.mode,
		fingerprint: fingerprintFor(p.mode, latestText),
		edits:       make(map[ComponentName]editOp),
		owned:       make(map[ComponentName]bool),
	}

	var conflicts []Conflict
	for _, c := range componentOrder {
		own := p.edits[c]
		isOwned := p.owned[c]
		originLit := componentOf(origin, c)
		latestLit := componentOf(latestParsed, c)

		if isOwned {
			rebased.edits[c] = own
			rebased.owned[c] = true
			// An authored edit conflicts whenever the latest value moved away
			// from the original value the edit was based on. Lexical
			// equivalence of the whole URNs does not hide the conflict.
			if originLit != latestLit {
				rightOp := OpReplaced
				if latestLit == "" {
					rightOp = OpDeleted
				}
				conflicts = append(conflicts, Conflict{
					Component: c,
					Base:      originLit,
					Left:      conflictLiteral(own),
					LeftOp:    conflictOp(own),
					Right:     latestLit,
					RightOp:   rightOp,
				})
			}
			continue
		}

		// Components the plan did not author: any upstream change (including
		// changes to a value carried by a previous rebase) is carried along.
		if originLit != latestLit {
			if latestLit == "" {
				rebased.edits[c] = editOp{intent: editDelete}
			} else {
				rebased.edits[c] = editOp{intent: editReplace, value: latestLit}
			}
			rebased.owned[c] = false
		}
	}

	if len(conflicts) > 0 {
		rebased.conflicts = conflicts
		return rebased, &MergeError{Conflicts: conflicts}
	}
	return rebased, nil
}

// JSON persistence types.
//
// "absent", "replace" and "delete" are distinct states: an edit is either not
// present at all, an object with op "replace" and a non-empty value, or an
// object with op "delete".
type editPlanDTO struct {
	Original          string             `json:"original"`
	OriginFingerprint string             `json:"originFingerprint"`
	Baseline          string             `json:"baseline,omitempty"`
	Mode              string             `json:"mode"`
	Fingerprint       string             `json:"fingerprint"`
	Edits             []componentEditDTO `json:"edits"`
	Conflicts         []conflictDTO      `json:"conflicts,omitempty"`
	ConflictDigest    string             `json:"conflictDigest,omitempty"`
}

type componentEditDTO struct {
	Component ComponentName `json:"component"`
	Op        string        `json:"op"`
	Value     string        `json:"value,omitempty"`
	Owned     bool          `json:"owned,omitempty"`
}

type conflictDTO struct {
	Component ComponentName `json:"component"`
	Base      string        `json:"base"`
	Left      string        `json:"left"`
	LeftOp    string        `json:"leftOp"`
	Right     string        `json:"right"`
	RightOp   string        `json:"rightOp"`
}

func modeString(mode ParsingMode) (string, error) {
	switch mode {
	case RFC2141Only:
		return "rfc2141", nil
	case RFC8141Only:
		return "rfc8141", nil
	case RFC7643Only:
		return "scim", nil
	default:
		return "", fmt.Errorf("unknown parsing mode %d", mode)
	}
}

func parseModeString(s string) (ParsingMode, error) {
	switch s {
	case "rfc2141":
		return RFC2141Only, nil
	case "rfc8141":
		return RFC8141Only, nil
	case "scim":
		return RFC7643Only, nil
	default:
		return Default, fmt.Errorf("unknown parsing mode %q", s)
	}
}

// MarshalJSON persists the plan, including its original text, parsing mode,
// fingerprint, edits and any unresolved conflicts.
func (p *EditPlan) MarshalJSON() ([]byte, error) {
	modeName, err := modeString(p.mode)
	if err != nil {
		return nil, err
	}
	dto := editPlanDTO{
		Original:          p.original,
		OriginFingerprint: fingerprintFor(p.mode, p.original),
		Baseline:          p.baseline,
		Mode:              modeName,
		Fingerprint:       p.fingerprint,
		Edits:             make([]componentEditDTO, 0, len(p.edits)),
	}
	for _, c := range componentOrder {
		op, ok := p.edits[c]
		if !ok {
			continue
		}
		e := componentEditDTO{Component: c}
		switch op.intent {
		case editReplace:
			e.Op = "replace"
			e.Value = op.value
		case editDelete:
			e.Op = "delete"
		default:
			return nil, fmt.Errorf("unknown edit intent for component %q", c)
		}
		e.Owned = p.owned[c]
		dto.Edits = append(dto.Edits, e)
	}
	for _, c := range p.conflicts {
		dto.Conflicts = append(dto.Conflicts, conflictDTO{
			Component: c.Component,
			Base:      c.Base,
			Left:      c.Left,
			LeftOp:    c.LeftOp.String(),
			Right:     c.Right,
			RightOp:   c.RightOp.String(),
		})
	}
	dto.ConflictDigest = conflictsDigest(dto.Fingerprint, dto.Edits, dto.Conflicts)
	return json.Marshal(dto)
}

// UnmarshalJSON restores a plan. Tampered fingerprints, unknown parsing
// modes, unknown or duplicated components, confused intents, invalid literals
// and inconsistent conflicts are all rejected.
func (p *EditPlan) UnmarshalJSON(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var dto editPlanDTO
	if err := dec.Decode(&dto); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("unexpected trailing JSON content")
	}
	var extra json.RawMessage
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("unexpected trailing JSON content")
	}

	mode, err := parseModeString(dto.Mode)
	if err != nil {
		return err
	}
	baseline := dto.Baseline
	if baseline == "" {
		baseline = dto.Original
	}
	if fingerprintFor(mode, baseline) != dto.Fingerprint {
		return errors.New("edit plan fingerprint does not match baseline text and parsing mode")
	}
	originFP := dto.OriginFingerprint
	if originFP == "" && baseline == dto.Original {
		originFP = dto.Fingerprint
	}
	if fingerprintFor(mode, dto.Original) != originFP {
		return errors.New("edit plan fingerprint does not match original text and parsing mode")
	}
	base, ok := Parse([]byte(baseline), WithParsingMode(mode))
	if !ok || base == nil || base.String() != baseline {
		return fmt.Errorf("baseline text is not a valid URN for parsing mode %d: %s", mode, baseline)
	}
	origin, parseOK := Parse([]byte(dto.Original), WithParsingMode(mode))
	if !parseOK || origin == nil || origin.String() != dto.Original {
		return fmt.Errorf("original text is not a valid URN for parsing mode %d: %s", mode, dto.Original)
	}

	edits := make(map[ComponentName]editOp)
	ownedSet := make(map[ComponentName]bool)
	for _, e := range dto.Edits {
		if !modeAllowsComponent(mode, e.Component) {
			return fmt.Errorf("unknown or unsupported component %q", e.Component)
		}
		if _, dup := edits[e.Component]; dup {
			return fmt.Errorf("duplicate edit intent for component %q", e.Component)
		}
		var op editOp
		switch e.Op {
		case "replace":
			if e.Value == "" {
				return fmt.Errorf("replace intent for component %q requires a non-empty value", e.Component)
			}
			op = editOp{intent: editReplace, value: e.Value}
		case "delete":
			if e.Value != "" {
				return fmt.Errorf("delete intent for component %q must not carry a value", e.Component)
			}
			op = editOp{intent: editDelete}
		default:
			return fmt.Errorf("unknown edit op %q for component %q", e.Op, e.Component)
		}
		if err := validateEdit(mode, e.Component, op); err != nil {
			return err
		}
		edits[e.Component] = op
		ownedSet[e.Component] = e.Owned
	}

	conflicts, err := decodeConflicts(dto.Conflicts, origin, base, mode, edits, ownedSet)
	if err != nil {
		return err
	}
	expectedDigest := conflictsDigest(dto.Fingerprint, dto.Edits, dto.Conflicts)
	if expectedDigest != dto.ConflictDigest {
		return errors.New("edit plan conflict digest does not match: conflicts were tampered with")
	}

	*p = EditPlan{
		original:    dto.Original,
		baseline:    baseline,
		mode:        mode,
		fingerprint: dto.Fingerprint,
		edits:       edits,
		owned:       ownedSet,
		conflicts:   conflicts,
	}
	return nil
}

func decodeConflictOp(s string) (ConflictOp, error) {
	switch s {
	case "replaced":
		return OpReplaced, nil
	case "deleted":
		return OpDeleted, nil
	default:
		return 0, fmt.Errorf("unknown conflict op %q", s)
	}
}

func decodeConflicts(dtos []conflictDTO, origin, base *URN, mode ParsingMode, edits map[ComponentName]editOp, owned map[ComponentName]bool) ([]Conflict, error) {
	if len(dtos) == 0 {
		return nil, nil
	}
	seen := make(map[ComponentName]bool)
	out := make([]Conflict, 0, len(dtos))
	for _, c := range dtos {
		if !modeAllowsComponent(mode, c.Component) {
			return nil, fmt.Errorf("unknown or unsupported component %q in conflict", c.Component)
		}
		if seen[c.Component] {
			return nil, fmt.Errorf("duplicate conflict for component %q", c.Component)
		}
		seen[c.Component] = true
		// Conflicts after a merge use the merge baseline; after a rebase they
		// use the original creation baseline. Accept either, and require the
		// recorded base to be one of them.
		baseLit := componentOf(base, c.Component)
		originLit := componentOf(origin, c.Component)
		if c.Base != baseLit && c.Base != originLit {
			return nil, fmt.Errorf("tampered base literal for component %q in conflict", c.Component)
		}
		// Full field-level tamper protection is provided by the HMAC digest;
		// the checks here also reject semantically inconsistent conflicts.
		leftOp, err := decodeConflictOp(c.LeftOp)
		if err != nil {
			return nil, err
		}
		rightOp, err := decodeConflictOp(c.RightOp)
		if err != nil {
			return nil, err
		}
		if rightOp == OpDeleted && c.Right != "" {
			return nil, fmt.Errorf("deleted right side for component %q must be empty", c.Component)
		}
		own, touched := edits[c.Component]
		if !touched {
			return nil, fmt.Errorf("conflict for component %q does not match recorded edits", c.Component)
		}
		if conflictOp(own) != leftOp || conflictLiteral(own) != c.Left {
			return nil, fmt.Errorf("tampered left side for component %q in conflict", c.Component)
		}
		if leftOp == OpDeleted && c.Left != "" {
			return nil, fmt.Errorf("deleted left side for component %q must be empty", c.Component)
		}
		if !owned[c.Component] {
			return nil, fmt.Errorf("conflict for component %q is not backed by an owned edit", c.Component)
		}
		out = append(out, Conflict{
			Component: c.Component,
			Base:      c.Base,
			Left:      c.Left,
			LeftOp:    leftOp,
			Right:     c.Right,
			RightOp:   rightOp,
		})
	}
	return out, nil
}
