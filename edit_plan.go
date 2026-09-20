package urn

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// Component names addressed by an edit plan.
const (
	ComponentNID        = "nid"
	ComponentNSS        = "nss"
	ComponentRComponent = "r-component"
	ComponentQComponent = "q-component"
	ComponentFragment   = "fragment"
)

// Components, in URN textual order.
var componentOrder = []string{
	ComponentNID,
	ComponentNSS,
	ComponentRComponent,
	ComponentQComponent,
	ComponentFragment,
}

// Sentinel errors reported while building, merging, rebasing or applying plans.
var (
	// ErrInvalidEditPlan means the edit plan cannot be built or deserialized.
	ErrInvalidEditPlan = errors.New("invalid edit plan")
	// ErrPlanConflict means two plans touch the same component on the same baseline.
	ErrPlanConflict = errors.New("edit plan conflict")
	// ErrBaselineMismatch means two plans do not share the same original text and mode.
	ErrBaselineMismatch = errors.New("edit plan baseline mismatch")
	// ErrInvalidComponent means a replacement literal does not satisfy its RFC component syntax.
	ErrInvalidComponent = errors.New("invalid edit plan component value")
)

type editAction string

const (
	actionReplace editAction = "replace"
	actionDelete  editAction = "delete"
)

// Edit is a single immutable component instruction for an EditPlan.
//
// Build edits with ReplaceNID, ReplaceNSS, ReplaceRComponent, ReplaceQComponent,
// ReplaceFragment, DeleteRComponent, DeleteQComponent and DeleteFragment.
type Edit struct {
	component string
	action    editAction
	value     string
}

// ReplaceNID replaces the namespace identifier with the given literal.
func ReplaceNID(value string) Edit {
	return Edit{component: ComponentNID, action: actionReplace, value: value}
}

// ReplaceNSS replaces the namespace-specific string with the given literal.
func ReplaceNSS(value string) Edit {
	return Edit{component: ComponentNSS, action: actionReplace, value: value}
}

// ReplaceRComponent replaces the r-component with the given literal.
//
// r-components only exist on RFC 8141 URNs.
func ReplaceRComponent(value string) Edit {
	return Edit{component: ComponentRComponent, action: actionReplace, value: value}
}

// ReplaceQComponent replaces the q-component with the given literal.
//
// q-components only exist on RFC 8141 URNs.
func ReplaceQComponent(value string) Edit {
	return Edit{component: ComponentQComponent, action: actionReplace, value: value}
}

// ReplaceFragment replaces the fragment with the given literal.
//
// Fragments only exist on RFC 8141 URNs.
func ReplaceFragment(value string) Edit {
	return Edit{component: ComponentFragment, action: actionReplace, value: value}
}

// DeleteRComponent removes the r-component (and its "?+" separator) from the URN.
func DeleteRComponent() Edit { return Edit{component: ComponentRComponent, action: actionDelete} }

// DeleteQComponent removes the q-component (and its "?=" separator) from the URN.
func DeleteQComponent() Edit { return Edit{component: ComponentQComponent, action: actionDelete} }

// DeleteFragment removes the fragment (and its "#" separator) from the URN.
func DeleteFragment() Edit { return Edit{component: ComponentFragment, action: actionDelete} }

// PlanConflict describes a component both sides edited on the same baseline.
//
// Base, Left and Right carry the raw component literals.
// A nil pointer means the component is absent on that side,
// which is the shape of a delete instruction.
type PlanConflict struct {
	Component string  `json:"component"`
	Base      *string `json:"base"`
	Left      *string `json:"left"`
	Right     *string `json:"right"`
}

// ComponentDiff is the component-level difference produced by applying a plan.
//
// From is empty when the component was added, To is empty when it was deleted.
type ComponentDiff struct {
	Component string `json:"component"`
	From      string `json:"from"`
	To        string `json:"to"`
}

// EditPlan is an immutable, serializable set of component edits.
//
// A plan remembers the exact original text it was created from, the parsing
// mode used to parse it, and a stable fingerprint of both.
// It can be merged with plans created on the same baseline, rebased onto a
// newer URN value, and applied to build a new validated URN.
type EditPlan struct {
	original    string
	mode        ParsingMode
	fingerprint string
	edits       map[string]Edit
	conflicts   []PlanConflict
}

func modeName(mode ParsingMode) (string, bool) {
	switch mode {
	case RFC2141Only:
		return "rfc2141", true
	case RFC7643Only:
		return "scim", true
	case RFC8141Only:
		return "rfc8141", true
	default:
		return "", false
	}
}

func kindForMode(mode ParsingMode) (Kind, bool) {
	switch mode {
	case RFC2141Only:
		return RFC2141, true
	case RFC7643Only:
		return RFC7643, true
	case RFC8141Only:
		return RFC8141, true
	default:
		return NONE, false
	}
}

// computeFingerprint builds a stable fingerprint of the original text and parsing mode.
func computeFingerprint(mode ParsingMode, original string) string {
	name, _ := modeName(mode)
	h := sha256.New()
	h.Write([]byte(name))
	h.Write([]byte{0})
	h.Write([]byte(original))
	return hex.EncodeToString(h.Sum(nil))
}

// OriginalText returns the exact URN text the plan was created from.
func (p *EditPlan) OriginalText() string {
	if p == nil {
		return ""
	}
	return p.original
}

// Mode returns the parsing mode the plan was created with.
func (p *EditPlan) Mode() ParsingMode {
	if p == nil {
		return Default
	}
	return p.mode
}

// Fingerprint returns the stable fingerprint of the plan baseline.
func (p *EditPlan) Fingerprint() string {
	if p == nil {
		return ""
	}
	return p.fingerprint
}

// Conflicts returns all conflicts recorded on the plan.
func (p *EditPlan) Conflicts() []PlanConflict {
	if p == nil || len(p.conflicts) == 0 {
		return nil
	}
	out := make([]PlanConflict, len(p.conflicts))
	copy(out, p.conflicts)
	return out
}

// Edit returns the instruction recorded for a component, and whether there is one.
func (p *EditPlan) Edit(component string) (Edit, bool) {
	if p == nil {
		return Edit{}, false
	}
	e, ok := p.edits[component]
	return e, ok
}

func (e Edit) Component() string { return e.component }
func (e Edit) String() string {
	if e.action == actionDelete {
		return fmt.Sprintf("%s:delete", e.component)
	}
	return fmt.Sprintf("%s:replace=%s", e.component, e.value)
}

func isHexDigit(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

func isAlnum(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

// scanPctEncoded validates a percent-escape at position i, returning the next position.
func scanPctEncoded(lit string, i int) (int, bool) {
	if i+2 >= len(lit) || lit[i] != '%' || !isHexDigit(lit[i+1]) || !isHexDigit(lit[i+2]) {
		return 0, false
	}
	return i + 3, true
}

// allowed2141 are the non-percent, literal characters permitted by RFC 2141 NSS
// (the "other" transients): ( ) + , - . : = @ ; $ _ ! * '
func allowed2141(c byte) bool {
	switch c {
	case '(', ')', '+', ',', '-', '.', ':', '=', '@', ';', '$', '_', '!', '*', '\'':
		return true
	}
	return false
}

// allowed8141Pchar adds the RFC 3986 sub-delims accepted by the Ragel pchar rule:
// ~ & (and the RFC 2141 set, excluding / ?).
func allowed8141Pchar(c byte) bool {
	switch c {
	case '~', '&':
		return true
	}
	return allowed2141(c) && c != '/' && c != '?'
}

// validatePercentEscapes checks every percent-escape of a literal uses two hex digits.
func validatePercentEscapes(lit string) bool {
	for i := 0; i < len(lit); i++ {
		if lit[i] == '%' {
			next, ok := scanPctEncoded(lit, i)
			if !ok {
				return false
			}
			i = next - 1
		} else if lit[i] > 127 {
			return false
		}
	}
	return true
}

// validateNID validates a replacement namespace identifier literal for the given mode.
//
// Structural rules (reserved names, informal namespaces) are ultimately enforced
// by re-parsing the assembled candidate text: this check only covers the literal alphabet.
func validateNID(lit string, mode ParsingMode) bool {
	if lit == "" {
		return false
	}
	if mode == RFC8141Only {
		// 2..32 alnum/dash chars, not starting or ending with a dash.
		if len(lit) < 2 || len(lit) > 32 || lit[0] == '-' || lit[len(lit)-1] == '-' {
			return false
		}
	} else {
		// 1..31 alnum/dash chars, not starting with a dash.
		if len(lit) > 32 || lit[0] == '-' {
			return false
		}
	}
	for i := 0; i < len(lit); i++ {
		c := lit[i]
		if !isAlnum(c) && c != '-' {
			return false
		}
	}
	return true
}

// validateNSS validates a replacement namespace-specific string literal.
func validateNSS(lit string, mode ParsingMode) bool {
	if lit == "" || !validatePercentEscapes(lit) {
		return false
	}
	switch mode {
	case RFC8141Only:
		// "?+" and "?=" inside the NSS would be read as r/q component starts.
		if strings.Contains(lit, "?+") || strings.Contains(lit, "?=") {
			return false
		}
		for i := 0; i < len(lit); i++ {
			if lit[i] == '%' {
				next, ok := scanPctEncoded(lit, i)
				if !ok {
					return false
				}
				i = next - 1
				continue
			}
			c := lit[i]
			if i > 0 && (c == '/' || c == '?') {
				continue
			}
			if !isAlnum(c) && !allowed8141Pchar(c) {
				return false
			}
		}
		return true
	case RFC2141Only, RFC7643Only:
		for i := 0; i < len(lit); i++ {
			if lit[i] == '%' {
				next, ok := scanPctEncoded(lit, i)
				if !ok {
					return false
				}
				i = next - 1
				continue
			}
			c := lit[i]
			if !isAlnum(c) && !allowed2141(c) {
				return false
			}
		}
		return true
	default:
		return false
	}
}

// forbiddenSeparator reports whether a component literal contains an unencoded
// sequence that the RFC 8141 grammar reads as a component boundary.
//
// rcomp may not contain "?+" (a second r) or "?=" (the q start).
// qcomp may not contain "?=" (a second q); a lone "?+" stays part of the q.
// Fragment content may not contain "#".
// Percent-escaped forms such as %3F and %23 are fine: the '%' is not '?'.
func forbiddenSeparator(lit, rq string) bool {
	if rq == "f" {
		return strings.ContainsRune(lit, '#')
	}
	ban := "?="
	if rq == "r" {
		ban = "?+"
	}
	idx := 0
	for {
		j := strings.IndexByte(lit[idx:], '?')
		if j < 0 {
			return false
		}
		pos := idx + j
		if pos+1 < len(lit) {
			seq := string([]byte{'?', lit[pos+1]})
			if seq == "?=" || seq == ban {
				return true
			}
		}
		idx = pos + 1
	}
}

// validateRQComponent validates a replacement r-component or q-component literal.
//
// The literal is the component content without its "?+"/"?=" separator.
// Empty literals are rejected: an empty component is indistinguishable from an
// absent one when serialized and RFC 8141 requires non-empty components.
func validateRQComponent(lit, which string) bool {
	if lit == "" || !validatePercentEscapes(lit) {
		return false
	}
	// component = pchar (pchar | "/" | "?")* — it must not start with "/" or "?".
	if lit[0] == '/' || lit[0] == '?' {
		return false
	}
	if forbiddenSeparator(lit, which) {
		return false
	}
	for i := 0; i < len(lit); i++ {
		if lit[i] == '%' {
			next, ok := scanPctEncoded(lit, i)
			if !ok {
				return false
			}
			i = next - 1
			continue
		}
		c := lit[i]
		if !isAlnum(c) && !allowed8141Pchar(c) && c != '/' && c != '?' {
			return false
		}
	}
	return true
}

// validateFragment validates a replacement fragment literal (without the "#" separator).
//
// An empty fragment literal is rejected: re-parsing cannot distinguish it from
// an absent fragment, so callers must use DeleteFragment instead.
// The "#" sequence is always the fragment separator and is rejected unencoded.
func validateFragment(lit string) bool {
	if lit == "" || strings.ContainsRune(lit, '#') || !validatePercentEscapes(lit) {
		return false
	}
	for i := 0; i < len(lit); i++ {
		if lit[i] == '%' {
			next, ok := scanPctEncoded(lit, i)
			if !ok {
				return false
			}
			i = next - 1
			continue
		}
		c := lit[i]
		if !isAlnum(c) && !allowed8141Pchar(c) && c != '/' && c != '?' {
			return false
		}
	}
	return true
}

// validateEdit checks an edit against the parsing mode before the plan is built.
func validateEdit(mode ParsingMode, e Edit) error {
	switch e.component {
	case ComponentNID:
		if e.action != actionReplace || !validateNID(e.value, mode) {
			return fmt.Errorf("%w: invalid nid literal %q", ErrInvalidComponent, e.value)
		}
	case ComponentNSS:
		if e.action != actionReplace || !validateNSS(e.value, mode) {
			return fmt.Errorf("%w: invalid nss literal %q", ErrInvalidComponent, e.value)
		}
	case ComponentRComponent, ComponentQComponent, ComponentFragment:
		if mode != RFC8141Only {
			return fmt.Errorf("%w: %s edits are only allowed in RFC 8141 mode", ErrInvalidEditPlan, e.component)
		}
		switch e.action {
		case actionReplace:
			var ok bool
			switch e.component {
			case ComponentFragment:
				ok = validateFragment(e.value)
			case ComponentRComponent:
				ok = validateRQComponent(e.value, "r")
			case ComponentQComponent:
				ok = validateRQComponent(e.value, "q")
			}
			if !ok {
				return fmt.Errorf("%w: invalid %s literal %q", ErrInvalidComponent, e.component, e.value)
			}
		case actionDelete:
		default:
			return fmt.Errorf("%w: unknown edit action for %s", ErrInvalidEditPlan, e.component)
		}
	default:
		return fmt.Errorf("%w: unknown component %q", ErrInvalidEditPlan, e.component)
	}
	return nil
}

// validateBaseline re-parses the URN string in the given mode and proves the
// parsed object round-trips byte-for-byte.
func validateBaseline(u *URN, mode ParsingMode) (*URN, string, error) {
	if u == nil || u.ID == "" || u.SS == "" {
		return nil, "", fmt.Errorf("%w: missing parsed URN", ErrInvalidEditPlan)
	}
	wantKind, ok := kindForMode(mode)
	if !ok || u.kind != wantKind {
		return nil, "", fmt.Errorf("%w: URN kind does not match parsing mode", ErrInvalidEditPlan)
	}
	original := u.String()
	if original == "" {
		return nil, "", fmt.Errorf("%w: cannot serialize URN", ErrInvalidEditPlan)
	}
	reparsed, err := NewMachine(WithParsingMode(mode)).Parse([]byte(original))
	if err != nil || reparsed == nil {
		return nil, "", fmt.Errorf("%w: baseline not parseable in the selected mode", ErrInvalidEditPlan)
	}
	if reparsed.String() != original {
		return nil, "", fmt.Errorf("%w: baseline does not round-trip byte-for-byte", ErrInvalidEditPlan)
	}
	return reparsed, original, nil
}

// NewEditPlan builds an immutable edit plan for a parsed URN.
//
// The mode must be the mode the URN was parsed with. Every edit is validated
// against the component syntax of that mode, and duplicate instructions for the
// same component are rejected. The plan stores the original text, mode and a
// fingerprint; no edit is applied here.
func NewEditPlan(u *URN, mode ParsingMode, edits ...Edit) (*EditPlan, error) {
	base, original, err := validateBaseline(u, mode)
	if err != nil {
		return nil, err
	}
	plan := &EditPlan{
		original:    original,
		mode:        mode,
		fingerprint: computeFingerprint(mode, original),
		edits:       map[string]Edit{},
	}
	for _, e := range edits {
		if _, known := componentIndex(e.component); !known {
			return nil, fmt.Errorf("%w: unknown component %q", ErrInvalidEditPlan, e.component)
		}
		if _, dup := plan.edits[e.component]; dup {
			return nil, fmt.Errorf("%w: duplicate edit for component %q", ErrInvalidEditPlan, e.component)
		}
		if err := validateEdit(mode, e); err != nil {
			return nil, err
		}
		plan.edits[e.component] = e
	}
	// Prove the full candidate parses in the original mode before accepting the plan.
	if _, err := validateCandidate(base, mode, plan.edits); err != nil {
		return nil, err
	}
	return plan, nil
}

// validateCandidate assembles the complete candidate text, re-parses it with
// the given mode and proves every edited literal lands on the intended
// component while unedited components stay byte-identical.
func validateCandidate(base *URN, mode ParsingMode, edits map[string]Edit) (*URN, error) {
	candidateText := assemble(base, edits)
	candidate, err := NewMachine(WithParsingMode(mode)).Parse([]byte(candidateText))
	if err != nil || candidate == nil {
		return nil, fmt.Errorf("%w: candidate rejected by the %s parser", ErrInvalidComponent, modeLabel(mode))
	}
	if candidate.String() != candidateText {
		return nil, fmt.Errorf("%w: candidate did not round-trip byte-for-byte", ErrInvalidComponent)
	}
	if !sameURNComponents(base, candidate, edits) {
		return nil, fmt.Errorf("%w: candidate component literals do not match the edit instructions", ErrInvalidComponent)
	}
	return candidate, nil
}

func modeLabel(mode ParsingMode) string {
	if name, ok := modeName(mode); ok {
		return name
	}
	return "configured"
}

func componentIndex(component string) (int, bool) {
	for i, c := range componentOrder {
		if c == component {
			return i, true
		}
	}
	return 0, false
}

// assemble builds the full candidate text from a baseline URN and the plan edits.
//
// Fields of the baseline that are not edited are copied byte-for-byte.
func assemble(base *URN, edits map[string]Edit) string {
	prefix := base.prefix
	nid := base.ID
	nss := base.SS
	r := base.rComponent
	q := base.qComponent
	f := base.fComponent

	if e, ok := edits[ComponentNID]; ok {
		nid = e.value
	}
	if e, ok := edits[ComponentNSS]; ok {
		nss = e.value
	}
	if e, ok := edits[ComponentRComponent]; ok {
		if e.action == actionDelete {
			r = ""
		} else {
			r = e.value
		}
	}
	if e, ok := edits[ComponentQComponent]; ok {
		if e.action == actionDelete {
			q = ""
		} else {
			q = e.value
		}
	}
	if e, ok := edits[ComponentFragment]; ok {
		if e.action == actionDelete {
			f = ""
		} else {
			f = e.value
		}
	}

	var b bytes.Buffer
	if prefix == "" {
		b.WriteString("urn")
	} else {
		b.WriteString(prefix)
	}
	b.WriteByte(':')
	b.WriteString(nid)
	b.WriteByte(':')
	b.WriteString(nss)
	if r != "" {
		b.WriteString("?+")
		b.WriteString(r)
	}
	if q != "" {
		b.WriteString("?=")
		b.WriteString(q)
	}
	if f != "" {
		b.WriteByte('#')
		b.WriteString(f)
	}
	return b.String()
}

// componentValue reads a component literal from a parsed URN.
func componentValue(u *URN, component string) string {
	switch component {
	case ComponentNID:
		return u.ID
	case ComponentNSS:
		return u.SS
	case ComponentRComponent:
		return u.rComponent
	case ComponentQComponent:
		return u.qComponent
	case ComponentFragment:
		return u.fComponent
	default:
		return ""
	}
}

// sameURNComponents proves the candidate parse carries exactly the edited values
// and leaves every unedited component byte-identical to the baseline.
func sameURNComponents(base, candidate *URN, edits map[string]Edit) bool {
	for _, component := range componentOrder {
		got := componentValue(candidate, component)
		if e, edited := edits[component]; edited {
			var want string
			if e.action == actionReplace {
				want = e.value
			}
			if got != want {
				return false
			}
		} else if got != componentValue(base, component) {
			return false
		}
	}
	return candidate.prefix == base.prefix
}

// Apply constructs the candidate URN, re-parses it with the original parsing mode
// and validates every component literal.
//
// On success it returns the new URN and a component-level diff.
// On failure the receiver and the baseline URN are left untouched; there is no
// half-applied state because the candidate is fully assembled and validated
// before a new URN is returned.
func (p *EditPlan) Apply() (*URN, []ComponentDiff, error) {
	if p == nil {
		return nil, nil, fmt.Errorf("%w: nil plan", ErrInvalidEditPlan)
	}
	if len(p.conflicts) > 0 {
		return nil, nil, fmt.Errorf("%w: cannot apply a plan with %d unresolved conflict(s)", ErrPlanConflict, len(p.conflicts))
	}
	base, err := NewMachine(WithParsingMode(p.mode)).Parse([]byte(p.original))
	if err != nil || base == nil {
		return nil, nil, fmt.Errorf("%w: baseline no longer parseable", ErrInvalidEditPlan)
	}
	candidate, err := validateCandidate(base, p.mode, p.edits)
	if err != nil {
		return nil, nil, err
	}

	var diffs []ComponentDiff
	for _, component := range componentOrder {
		from := componentValue(base, component)
		to := componentValue(candidate, component)
		if from != to {
			diffs = append(diffs, ComponentDiff{Component: component, From: from, To: to})
		}
	}
	return candidate, diffs, nil
}

func literalPtr(present bool, value string) *string {
	if !present {
		return nil
	}
	v := value
	return &v
}

// editLiteral returns the post-edit view of a component instruction:
// false means the component is deleted by the instruction.
func editLiteral(e Edit) (present bool, value string) {
	if e.action == actionDelete {
		return false, ""
	}
	return true, e.value
}

// Merge combines two plans created on the same baseline.
//
// Edits to different components accumulate regardless of merge order.
// When both plans edit the same component, the conflict is recorded with the
// raw base, left and right component literals (nil marks an absent or deleted
// component). All conflicts are reported at once; equivalence of candidates
// never resolves a conflict automatically.
//
// The returned plan is immutable and reports the same conflicts in component
// order; it cannot be applied while conflicts remain.
func (p *EditPlan) Merge(other *EditPlan) (*EditPlan, error) {
	if p == nil || other == nil {
		return nil, fmt.Errorf("%w: cannot merge nil plans", ErrInvalidEditPlan)
	}
	if p.mode != other.mode || p.original != other.original {
		return nil, fmt.Errorf("%w: plans must share the same original text and parsing mode", ErrBaselineMismatch)
	}
	if len(p.conflicts) > 0 || len(other.conflicts) > 0 {
		return nil, fmt.Errorf("%w: cannot merge plans that already contain conflicts", ErrPlanConflict)
	}

	base, err := NewMachine(WithParsingMode(p.mode)).Parse([]byte(p.original))
	if err != nil || base == nil || base.String() != p.original {
		return nil, fmt.Errorf("%w: baseline no longer parseable", ErrInvalidEditPlan)
	}

	merged := &EditPlan{
		original:    p.original,
		mode:        p.mode,
		fingerprint: p.fingerprint,
		edits:       map[string]Edit{},
	}
	var conflicts []PlanConflict
	for _, component := range componentOrder {
		le, lok := p.edits[component]
		re, rok := other.edits[component]
		switch {
		case lok && rok:
			basePtr := literalPtr(componentValue(base, component) != "", componentValue(base, component))
			_, lv := editLiteral(le)
			_, rv := editLiteral(re)
			conflicts = append(conflicts, PlanConflict{
				Component: component,
				Base:      basePtr,
				Left:      literalPtr(le.action == actionReplace, lv),
				Right:     literalPtr(re.action == actionReplace, rv),
			})
		case lok:
			merged.edits[component] = le
		case rok:
			merged.edits[component] = re
		}
	}
	if len(conflicts) > 0 {
		merged.conflicts = conflicts
	}
	return merged, nil
}

// Rebase replays the plan onto a newer value of the same URN.
//
// Components changed in latest but untouched by this plan are carried over.
// When both the plan and latest touched the same component, a conflict carrying
// base, plan and latest literals is reported — even when the URNs remain
// lexically equivalent. The returned plan keeps the original baseline text,
// mode and fingerprint and cannot be applied while conflicts remain.
func (p *EditPlan) Rebase(latest *URN) (*EditPlan, error) {
	if p == nil {
		return nil, fmt.Errorf("%w: nil plan", ErrInvalidEditPlan)
	}
	if len(p.conflicts) > 0 {
		return nil, fmt.Errorf("%w: cannot rebase a plan that already contains conflicts", ErrPlanConflict)
	}
	if latest == nil {
		return nil, fmt.Errorf("%w: missing latest URN", ErrInvalidEditPlan)
	}
	if wantKind, ok := kindForMode(p.mode); !ok || latest.kind != wantKind {
		return nil, fmt.Errorf("%w: latest URN parsing mode does not match the plan mode", ErrBaselineMismatch)
	}
	latestText := latest.String()
	if latestText == p.original {
		same := &EditPlan{
			original:    p.original,
			mode:        p.mode,
			fingerprint: p.fingerprint,
			edits:       map[string]Edit{},
		}
		for k, v := range p.edits {
			same.edits[k] = v
		}
		return same, nil
	}

	base, err := NewMachine(WithParsingMode(p.mode)).Parse([]byte(p.original))
	if err != nil || base == nil {
		return nil, fmt.Errorf("%w: baseline no longer parseable", ErrInvalidEditPlan)
	}

	rebased := &EditPlan{
		original:    latestText,
		mode:        p.mode,
		fingerprint: computeFingerprint(p.mode, latestText),
		edits:       map[string]Edit{},
	}
	var conflicts []PlanConflict
	for _, component := range componentOrder {
		oldValue := componentValue(base, component)
		newValue := componentValue(latest, component)
		latestChanged := oldValue != newValue
		if e, touched := p.edits[component]; touched {
			if latestChanged {
				_, pv := editLiteral(e)
				conflicts = append(conflicts, PlanConflict{
					Component: component,
					Base:      literalPtr(oldValue != "", oldValue),
					Left:      literalPtr(e.action == actionReplace, pv),
					Right:     literalPtr(newValue != "", newValue),
				})
			} else {
				rebased.edits[component] = e
			}
			continue
		}
		// Untouched components are carried implicitly: the rebased plan stores
		// latest as its original text, so their new literals need no instruction.
	}
	if len(conflicts) > 0 {
		rebased.conflicts = conflicts
	}
	return rebased, nil
}

type wireEdit struct {
	Action string `json:"action"`
	Value  string `json:"value,omitempty"`
}

type wirePlan struct {
	Original    string              `json:"original"`
	Mode        string              `json:"mode"`
	Fingerprint string              `json:"fingerprint"`
	Edits       map[string]wireEdit `json:"edits"`
}

// MarshalJSON persists the plan, keeping the three edit intentions distinct:
// an absent component key means "no instruction", delete carries no value,
// replace carries the new literal.
func (p *EditPlan) MarshalJSON() ([]byte, error) {
	if p == nil {
		return []byte("null"), nil
	}
	if len(p.conflicts) > 0 {
		return nil, fmt.Errorf("%w: cannot marshal a plan with unresolved conflicts", ErrPlanConflict)
	}
	name, ok := modeName(p.mode)
	if !ok {
		return nil, fmt.Errorf("%w: unsupported parsing mode", ErrInvalidEditPlan)
	}
	edits := map[string]wireEdit{}
	keys := make([]string, 0, len(p.edits))
	for component := range p.edits {
		keys = append(keys, component)
	}
	sort.Strings(keys)
	for _, component := range keys {
		e := p.edits[component]
		switch e.action {
		case actionReplace:
			edits[component] = wireEdit{Action: string(actionReplace), Value: e.value}
		case actionDelete:
			edits[component] = wireEdit{Action: string(actionDelete)}
		default:
			return nil, fmt.Errorf("%w: unknown edit action for %q", ErrInvalidEditPlan, component)
		}
	}
	return json.Marshal(wirePlan{
		Original:    p.original,
		Mode:        name,
		Fingerprint: p.fingerprint,
		Edits:       edits,
	})
}

func hasExplicitValue(rawEdits json.RawMessage, component string) bool {
	var edits map[string]map[string]json.RawMessage
	if err := json.Unmarshal(rawEdits, &edits); err != nil {
		return false
	}
	obj, ok := edits[component]
	if !ok {
		return false
	}
	_, has := obj["value"]
	return has
}

// UnmarshalJSON reconstructs a plan from JSON, rejecting unknown components,
// unknown/duplicate intentions, mode/fingerprint tampering and mode mismatches
// before any new URN could be produced.
func (p *EditPlan) UnmarshalJSON(data []byte) error {
	if err := rejectDuplicateJSONKeys(data); err != nil {
		return err
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidEditPlan, err)
	}
	if _, ok := raw["original"]; !ok {
		return fmt.Errorf("%w: missing original text", ErrInvalidEditPlan)
	}
	if _, ok := raw["mode"]; !ok {
		return fmt.Errorf("%w: missing parsing mode", ErrInvalidEditPlan)
	}
	if _, ok := raw["fingerprint"]; !ok {
		return fmt.Errorf("%w: missing fingerprint", ErrInvalidEditPlan)
	}

	var wire wirePlan
	if err := json.Unmarshal(data, &wire); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidEditPlan, err)
	}
	mode := Default
	switch wire.Mode {
	case "rfc2141":
		mode = RFC2141Only
	case "scim":
		mode = RFC7643Only
	case "rfc8141":
		mode = RFC8141Only
	default:
		return fmt.Errorf("%w: unknown parsing mode %q", ErrInvalidEditPlan, wire.Mode)
	}
	if wire.Fingerprint != computeFingerprint(mode, wire.Original) {
		return fmt.Errorf("%w: fingerprint mismatch", ErrInvalidEditPlan)
	}
	base, err := NewMachine(WithParsingMode(mode)).Parse([]byte(wire.Original))
	if err != nil || base == nil || base.String() != wire.Original {
		return fmt.Errorf("%w: original text does not parse in the stored mode", ErrInvalidEditPlan)
	}

	edits := map[string]Edit{}
	components := make([]string, 0, len(wire.Edits))
	for component := range wire.Edits {
		if _, known := componentIndex(component); !known {
			return fmt.Errorf("%w: unknown component %q", ErrInvalidEditPlan, component)
		}
		components = append(components, component)
	}
	sort.Strings(components)
	for _, component := range components {
		we := wire.Edits[component]
		e := Edit{component: component}
		switch editAction(we.Action) {
		case actionReplace:
			e.action = actionReplace
			e.value = we.Value
		case actionDelete:
			e.action = actionDelete
		default:
			return fmt.Errorf("%w: unknown action %q for %q", ErrInvalidEditPlan, we.Action, component)
		}
		if e.action == actionDelete && hasExplicitValue(raw["edits"], component) {
			return fmt.Errorf("%w: delete instruction for %q must not carry a value", ErrInvalidEditPlan, component)
		}
		if e.action == actionReplace && !hasExplicitValue(raw["edits"], component) {
			return fmt.Errorf("%w: replace instruction for %q requires a value", ErrInvalidEditPlan, component)
		}
		if err := validateEdit(mode, e); err != nil {
			return err
		}
		edits[component] = e
	}

	*p = EditPlan{
		original:    wire.Original,
		mode:        mode,
		fingerprint: wire.Fingerprint,
		edits:       edits,
	}
	return nil
}

// rejectDuplicateJSONKeys walks the raw JSON and rejects duplicate object keys.
//
// It also rejects unknown top-level fields, unknown component keys and
// unknown fields inside an edit object.
func rejectDuplicateJSONKeys(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	topAllowed := map[string]bool{"original": true, "mode": true, "fingerprint": true, "edits": true}
	editFieldAllowed := map[string]bool{"action": true, "value": true}
	var walk func(depth int, keyPath []string) error
	walk = func(depth int, keyPath []string) error {
		t, err := dec.Token()
		if err != nil {
			if err.Error() == "EOF" {
				return nil
			}
			return err
		}
		delim, ok := t.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return err
				}
				key, _ := kt.(string)
				switch {
				case depth == 0:
					if !topAllowed[key] {
						return fmt.Errorf("%w: unknown field %q", ErrInvalidEditPlan, key)
					}
				case depth == 1 && len(keyPath) == 1 && keyPath[0] == "edits":
					if _, known := componentIndex(key); !known {
						return fmt.Errorf("%w: unknown component %q", ErrInvalidEditPlan, key)
					}
				case depth == 2 && len(keyPath) == 2 && keyPath[0] == "edits":
					if !editFieldAllowed[key] {
						return fmt.Errorf("%w: unknown field %q in edit for %q", ErrInvalidEditPlan, key, keyPath[1])
					}
				}
				pathKey := strings.Join(keyPath, ".") + "." + key
				if seen[pathKey] {
					return fmt.Errorf("%w: duplicate key %q", ErrInvalidEditPlan, pathKey)
				}
				seen[pathKey] = true
				if err := walk(depth+1, append(keyPath, key)); err != nil {
					return err
				}
			}
			_, err := dec.Token()
			return err
		case '[':
			for dec.More() {
				if err := walk(depth+1, keyPath); err != nil {
					return err
				}
			}
			_, err := dec.Token()
			return err
		}
		return nil
	}
	if err := walk(0, nil); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidEditPlan, err)
	}
	return nil
}
