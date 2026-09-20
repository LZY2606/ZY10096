package urn_test

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/leodido/go-urn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func mustParse(t *testing.T, s string, mode urn.ParsingMode) *urn.URN {
	t.Helper()
	u, ok := urn.Parse([]byte(s), urn.WithParsingMode(mode))
	require.True(t, ok, "failed to parse %q", s)
	require.NotNil(t, u)
	return u
}

func TestEditPlanRegressionOptionalComponentsPreservedAndDeleted(t *testing.T) {
	original := "URN:EXAMPLE:A%2CB?+Rval?=Qval#Frag"
	u := mustParse(t, original, urn.RFC8141Only)

	// No edits: the candidate must be reconstructed byte-for-byte.
	plan, err := urn.NewEditPlan(u)
	require.NoError(t, err)
	nu, diff, err := plan.Apply()
	require.NoError(t, err)
	assert.Equal(t, original, nu.String())
	assert.Empty(t, diff.Changes)

	// Delete each optional component one at a time, separators must go too.
	cases := []struct {
		name string
		opt  urn.EditOption
		want string
		comp urn.ComponentName
	}{
		{"fragment", urn.DeleteFragment(), "URN:EXAMPLE:A%2CB?+Rval?=Qval", urn.ComponentFragment},
		{"q", urn.DeleteQComponent(), "URN:EXAMPLE:A%2CB?+Rval#Frag", urn.ComponentQ},
		{"r", urn.DeleteRComponent(), "URN:EXAMPLE:A%2CB?=Qval#Frag", urn.ComponentR},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, pErr := urn.NewEditPlan(u, tc.opt)
			require.NoError(t, pErr)
			got, d, aErr := p.Apply()
			require.NoError(t, aErr)
			assert.Equal(t, tc.want, got.String())
			ch := d.Changes[tc.comp]
			assert.True(t, ch.Deleted)
			assert.Empty(t, ch.New)
		})
	}

	// Delete r and q together leaves only the fragment.
	p, err := urn.NewEditPlan(u, urn.DeleteRComponent(), urn.DeleteQComponent())
	require.NoError(t, err)
	got, _, err := p.Apply()
	require.NoError(t, err)
	assert.Equal(t, "URN:EXAMPLE:A%2CB#Frag", got.String())
}

func TestEditPlanRegressionEmptyRAndQRejected(t *testing.T) {
	u := mustParse(t, "urn:example:a", urn.RFC8141Only)

	_, err := urn.NewEditPlan(u, urn.ReplaceRComponent(""))
	require.Error(t, err)
	_, err = urn.NewEditPlan(u, urn.ReplaceQComponent(""))
	require.Error(t, err)
	// Literal consisting of only a separator-looking start is rejected too.
	_, err = urn.NewEditPlan(u, urn.ReplaceRComponent("/"))
	require.Error(t, err)
	_, err = urn.NewEditPlan(u, urn.ReplaceQComponent("x?=y"))
	require.Error(t, err)
}

func TestEditPlanRegressionPercentCaseFidelity(t *testing.T) {
	original := "URN:EXAMPLE:A%2cB?+r%2a"
	u := mustParse(t, original, urn.RFC8141Only)

	plan, err := urn.NewEditPlan(u, urn.ReplaceNSS("Z%2Fw"))
	require.NoError(t, err)
	// Original text and fingerprint are preserved on the plan.
	assert.Equal(t, original, plan.OriginalText())
	assert.Len(t, plan.Fingerprint(), 64)

	got, _, err := plan.Apply()
	require.NoError(t, err)
	// Prefix/NID case unchanged, untouched r-component keeps its own case,
	// replaced NSS keeps uppercase %2F, old %2c casing no longer relevant.
	assert.Equal(t, "URN:EXAMPLE:Z%2Fw?+r%2a", got.String())

	// Unchanged plan reconstructs lowercase %2c exactly.
	noop, err := urn.NewEditPlan(u)
	require.NoError(t, err)
	nu, _, err := noop.Apply()
	require.NoError(t, err)
	assert.Equal(t, original, nu.String())
	assert.True(t, u.Equal(nu))
}

func TestEditPlanRegressionEncodedQuestionAndHash(t *testing.T) {
	u := mustParse(t, "urn:example:a", urn.RFC8141Only)
	// Percent-encoded ? and # stay inside their components.
	p, err := urn.NewEditPlan(u,
		urn.ReplaceRComponent("x%3Fy"),
		urn.ReplaceQComponent("q%23z"),
		urn.ReplaceFragment("f%3Fg%23h"),
	)
	require.NoError(t, err)
	got, d, err := p.Apply()
	require.NoError(t, err)
	assert.Equal(t, "urn:example:a?+x%3Fy?=q%23z#f%3Fg%23h", got.String())
	assert.True(t, d.Changes[urn.ComponentR].Added)
	assert.True(t, d.Changes[urn.ComponentQ].Added)
	assert.True(t, d.Changes[urn.ComponentFragment].Added)

	// Raw, unencoded separators must be rejected.
	_, err = urn.NewEditPlan(u, urn.ReplaceFragment("f#x"))
	require.Error(t, err)
	_, err = urn.NewEditPlan(u, urn.ReplaceRComponent("x?=y"))
	require.Error(t, err)
	// Incomplete escapes and raw Unicode are rejected as well.
	_, err = urn.NewEditPlan(u, urn.ReplaceNSS("a%2"))
	require.Error(t, err)
	_, err = urn.NewEditPlan(u, urn.ReplaceNSS("a%\u00e9"))
	require.Error(t, err)
}

func TestEditPlanRegressionSCIMViewRefresh(t *testing.T) {
	original := "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	u := mustParse(t, original, urn.RFC7643Only)
	require.True(t, u.IsSCIM())
	before := u.SCIM()
	require.NotNil(t, before)
	assert.Equal(t, "messages", before.Name)
	assert.Equal(t, "2.0:ListResponse", before.Other)

	plan, err := urn.NewEditPlan(u, urn.ReplaceNSS("schemas:core:2.0:User"))
	require.NoError(t, err)
	got, _, err := plan.Apply()
	require.NoError(t, err)
	assert.Equal(t, "urn:ietf:params:scim:schemas:core:2.0:User", got.String())
	require.True(t, got.IsSCIM())
	view := got.SCIM()
	require.NotNil(t, view)
	assert.Equal(t, "schemas", view.Type.String())
	assert.Equal(t, "core", view.Name)
	assert.Equal(t, "2.0:User", view.Other)
	// The old SCIM view must not have been mutated.
	assert.Equal(t, "messages", before.Name)

	// 8141-only components cannot be used with SCIM URNs.
	_, err = urn.NewEditPlan(u, urn.ReplaceRComponent("r"))
	require.Error(t, err)
	_, err = urn.NewEditPlan(u, urn.DeleteFragment())
	require.Error(t, err)
	// SCIM nss must remain a valid SCIM suffix.
	_, err = urn.NewEditPlan(u, urn.ReplaceNSS("a b"))
	require.Error(t, err)
	_, err = urn.NewEditPlan(u, urn.ReplaceNID("example"))
	require.Error(t, err)
}

func marshalHeader(t *testing.T, mode urn.ParsingMode, original string, editsJSON string) string {
	t.Helper()
	u := mustParse(t, original, mode)
	p, err := urn.NewEditPlan(u)
	require.NoError(t, err)
	raw, err := json.Marshal(p)
	require.NoError(t, err)
	var head map[string]interface{}
	require.NoError(t, json.Unmarshal(raw, &head))
	var edits []interface{}
	if editsJSON != "" {
		require.NoError(t, json.Unmarshal([]byte(editsJSON), &edits))
	}
	head["edits"] = edits
	if mode == urn.RFC7643Only {
		head["mode"] = "scim"
	}
	out, err := json.Marshal(head)
	require.NoError(t, err)
	return string(out)
}

func TestEditPlanRegressionJSONRoundTripAndTamper(t *testing.T) {
	u := mustParse(t, "urn:example:a?+old#frag", urn.RFC8141Only)
	plan, err := urn.NewEditPlan(u,
		urn.ReplaceRComponent("new"),
		urn.DeleteFragment(),
	)
	require.NoError(t, err)

	raw, err := json.Marshal(plan)
	require.NoError(t, err)
	require.Contains(t, string(raw), `"op":"replace"`)
	require.Contains(t, string(raw), `"op":"delete"`)
	require.Contains(t, string(raw), `"mode":"rfc8141"`)

	var restored urn.EditPlan
	require.NoError(t, json.Unmarshal(raw, &restored))
	got, _, err := restored.Apply()
	require.NoError(t, err)
	assert.Equal(t, "urn:example:a?+new", got.String())
	assert.Equal(t, plan.Fingerprint(), restored.Fingerprint())
	assert.Equal(t, plan.OriginalText(), restored.OriginalText())

	// Directly tampered headers are rejected before any URN is produced.
	badHeader := []string{
		`{"original":"urn:example:a?+old#frag","mode":"rfc8141","fingerprint":"deadbeef","edits":[]}`,
		`{"original":"urn:example:a?+old#frag","mode":"bogus","fingerprint":"x","edits":[]}`,
	}
	for _, payload := range badHeader {
		var p urn.EditPlan
		require.Error(t, json.Unmarshal([]byte(payload), &p), payload)
	}

	// Confused intents / unknown fields / duplicated intents, with a valid
	// fingerprint binding so the only problem can be tampered edit content.
	badEdits := []string{
		`[{"component":"bogus","op":"delete"}]`,
		`[{"component":"r-component","op":"delete"}]`,
		`[{"component":"nss","op":"delete","value":"x"}]`,
		`[{"component":"nss","op":"replace"}]`,
		`[{"component":"nss","op":"frobnicate","value":"x"}]`,
		`[{"component":"nss","op":"replace","value":"x"},{"component":"nss","op":"replace","value":"y"}]`,
		`[{"component":"nss","op":"replace","value":"a b"}]`,
		`[{"component":"nss","op":"replace","value":"a%zz"}]`,
		`[{"component":"nss","op":"replace","value":"a b"}]`,
	}
	for _, edits := range badEdits {
		payload := marshalHeader(t, urn.RFC2141Only, "urn:example:a", edits)
		var p urn.EditPlan
		require.Error(t, json.Unmarshal([]byte(payload), &p), edits)
	}
	// Unknown top-level field.
	var p urn.EditPlan
	require.Error(t, json.Unmarshal([]byte(`{"original":"x","mode":"rfc2141","fingerprint":"y","edits":[],"extra":1}`), &p))
}

func TestEditPlanRegressionMultipleConflictsAtOnce(t *testing.T) {
	base := mustParse(t, "urn:example:a?+r1?=q1#f1", urn.RFC8141Only)
	left, err := urn.NewEditPlan(base,
		urn.ReplaceNSS("L"),
		urn.ReplaceRComponent("rL"),
		urn.ReplaceQComponent("qL"),
	)
	require.NoError(t, err)
	right, err := urn.NewEditPlan(base,
		urn.ReplaceNSS("L"),
		urn.ReplaceRComponent("rL"),
		urn.DeleteQComponent(),
		urn.ReplaceFragment("fR"),
	)
	require.NoError(t, err)

	merged, mergeErr := left.Merge(right)
	require.Error(t, mergeErr)
	var mErr *urn.MergeError
	require.True(t, errors.As(mergeErr, &mErr))
	// nss (identical literals), r (identical literals), q (replace vs delete)
	// are conflicts even when literals coincide; fragment is only touched by
	// the right side so it merges cleanly -> 3 conflicts in one report.
	require.Len(t, mErr.Conflicts, 3)

	byName := map[urn.ComponentName]urn.Conflict{}
	for _, c := range mErr.Conflicts {
		byName[c.Component] = c
	}
	c := byName[urn.ComponentNSS]
	assert.Equal(t, "a", c.Base)
	assert.Equal(t, "L", c.Left)
	assert.Equal(t, "L", c.Right)
	c = byName[urn.ComponentQ]
	assert.Equal(t, "q1", c.Base)
	assert.Equal(t, "qL", c.Left)
	assert.Equal(t, urn.OpReplaced, c.LeftOp)
	assert.Equal(t, "", c.Right)
	assert.Equal(t, urn.OpDeleted, c.RightOp)
	_, fragmentConflict := byName[urn.ComponentFragment]
	assert.False(t, fragmentConflict)

	// Even identical candidate literals do not auto-resolve conflicts.
	_, _, err = merged.Apply()
	assert.ErrorIs(t, err, urn.ErrPlanHasConflicts)

	// Conflicted plans survive a JSON round-trip and still cannot be applied.
	raw, err := json.Marshal(merged)
	require.NoError(t, err)
	var restored urn.EditPlan
	require.NoError(t, json.Unmarshal(raw, &restored))
	assert.Len(t, restored.Conflicts(), 3)
	_, _, err = restored.Apply()
	assert.ErrorIs(t, err, urn.ErrPlanHasConflicts)
}

func TestEditPlanRegressionMergeOrderIndependent(t *testing.T) {
	base := mustParse(t, "urn:example:a?+r1?=q1#f1", urn.RFC8141Only)
	left, err := urn.NewEditPlan(base,
		urn.ReplaceNID("left-nid"),
		urn.ReplaceNSS("Lss"),
		urn.DeleteFragment(),
	)
	require.NoError(t, err)
	right, err := urn.NewEditPlan(base,
		urn.ReplaceRComponent("rR"),
		urn.ReplaceQComponent("qR"),
	)
	require.NoError(t, err)

	lr, err := left.Merge(right)
	require.NoError(t, err)
	rl, err := right.Merge(left)
	require.NoError(t, err)

	gotLR, _, err := lr.Apply()
	require.NoError(t, err)
	gotRL, _, err := rl.Apply()
	require.NoError(t, err)
	assert.Equal(t, gotLR.String(), gotRL.String())
	assert.Equal(t, "urn:left-nid:Lss?+rR?=qR", gotLR.String())

	// Different baselines or modes cannot be merged.
	otherBase := mustParse(t, "urn:example:b?+r1?=q1#f1", urn.RFC8141Only)
	other, err := urn.NewEditPlan(otherBase, urn.ReplaceFragment("x"))
	require.NoError(t, err)
	_, err = left.Merge(other)
	require.Error(t, err)

	scim, err := urn.NewEditPlan(mustParse(t, "urn:ietf:params:scim:schemas:core", urn.RFC7643Only))
	require.NoError(t, err)
	_, err = left.Merge(scim)
	require.Error(t, err)
}

func TestEditPlanRegressionStaleBaselineRebase(t *testing.T) {
	base := mustParse(t, "urn:example:a?+r1?=q1#f1", urn.RFC8141Only)

	// Latest value changed only components the plan does not touch: carry them.
	plan, err := urn.NewEditPlan(base, urn.ReplaceNSS("mine"))
	require.NoError(t, err)
	latest := mustParse(t, "urn:example:a?+r2?=q2#f2", urn.RFC8141Only)
	rebased, err := plan.Rebase(latest)
	require.NoError(t, err)
	assert.Equal(t, base.String(), rebased.OriginalText(), "original text is immutable")
	assert.Equal(t, latest.String(), rebased.BaselineText())
	got, d, err := rebased.Apply()
	require.NoError(t, err)
	assert.Equal(t, "urn:example:mine?+r2?=q2#f2", got.String())
	assert.Equal(t, "r2", d.Changes[urn.ComponentR].New)
	assert.Equal(t, "q2", d.Changes[urn.ComponentQ].New)
	assert.Equal(t, "f2", d.Changes[urn.ComponentFragment].New)

	// A deletion of an untouched optional component is carried as a delete.
	planDel, err := urn.NewEditPlan(base, urn.ReplaceNSS("mine"))
	require.NoError(t, err)
	latestDel := mustParse(t, "urn:example:a?=q1#f1", urn.RFC8141Only)
	rebasedDel, err := planDel.Rebase(latestDel)
	require.NoError(t, err)
	gotDel, dDel, err := rebasedDel.Apply()
	require.NoError(t, err)
	assert.Equal(t, "urn:example:mine?=q1#f1", gotDel.String())
	_ = gotDel
	assert.True(t, dDel.Changes[urn.ComponentR].Deleted)

	// Latest value touched a component the plan also touched: conflict, even
	// though the whole URNs remain lexically equivalent after normalization.
	conflictPlan, err := urn.NewEditPlan(base, urn.ReplaceNSS("a"))
	require.NoError(t, err)
	conflicting := mustParse(t, "urn:example:a?+r1?=q1#f1", urn.RFC8141Only)
	_, err = conflictPlan.Rebase(conflicting)
	// Literally identical here: no upstream change -> clean rebase.
	assert.NoError(t, err)

	latest2 := mustParse(t, "urn:example:A?+r1?=q1#f1", urn.RFC8141Only)
	reb, rerr := conflictPlan.Rebase(latest2)
	require.Error(t, rerr)
	var mErr *urn.MergeError
	require.True(t, errors.As(rerr, &mErr))
	require.Len(t, mErr.Conflicts, 1)
	c := mErr.Conflicts[0]
	assert.Equal(t, urn.ComponentNSS, c.Component)
	assert.Equal(t, "a", c.Base)
	assert.Equal(t, "a", c.Left)
	assert.Equal(t, "A", c.Right)
	_, _, err = reb.Apply()
	assert.ErrorIs(t, err, urn.ErrPlanHasConflicts)

	// A deletion upstream of a component the plan edits is a conflict too.
	delPlan, err := urn.NewEditPlan(base, urn.ReplaceRComponent("mine"))
	require.NoError(t, err)
	latest3 := mustParse(t, "urn:example:a?=q1#f1", urn.RFC8141Only)
	_, err = delPlan.Rebase(latest3)
	require.Error(t, err)
}

func TestEditPlanRegressionModeRestrictions(t *testing.T) {
	u2141 := mustParse(t, "urn:example:a", urn.RFC2141Only)
	for _, opt := range []urn.EditOption{
		urn.ReplaceRComponent("x"),
		urn.ReplaceQComponent("x"),
		urn.ReplaceFragment("x"),
		urn.DeleteRComponent(),
		urn.DeleteQComponent(),
		urn.DeleteFragment(),
	} {
		_, err := urn.NewEditPlan(u2141, opt)
		require.Error(t, err)
	}
	uSCIM := mustParse(t, "urn:ietf:params:scim:schemas:core", urn.RFC7643Only)
	_, err := urn.NewEditPlan(uSCIM, urn.ReplaceRComponent("x"))
	require.Error(t, err)

	// Fragments cannot be added to a 2141 URN.
	plan, err := urn.NewEditPlan(u2141)
	require.NoError(t, err)
	_ = plan
}

func TestEditPlanRegressionNoOpIsByteFaithful(t *testing.T) {
	// Prefix case, NID case, percent hex letter case, existing separators.
	original := "UrN:MyNID:x%2Cy%2cZ?+R%2a?=Q%2A#F%2fG"
	u := mustParse(t, original, urn.RFC8141Only)
	p, err := urn.NewEditPlan(u)
	require.NoError(t, err)
	got, d, err := p.Apply()
	require.NoError(t, err)
	assert.Equal(t, original, got.String())
	assert.Empty(t, d.Changes)

	// Marshal of the resulting URN keeps the literal spelling too.
	raw, err := json.Marshal(got)
	require.NoError(t, err)
	assert.Equal(t, `"`+original+`"`, string(raw))
	// Normalize and Equal semantics unchanged.
	nu := got.Normalize()
	assert.Equal(t, "urn", nu.String()[:3])
	assert.True(t, u.Equal(got))
}

func TestEditPlanRegressionDeleteDeleteConverges(t *testing.T) {
	base := mustParse(t, "urn:example:a?+r1#f1", urn.RFC8141Only)
	left, err := urn.NewEditPlan(base, urn.DeleteRComponent())
	require.NoError(t, err)
	right, err := urn.NewEditPlan(base, urn.DeleteRComponent())
	require.NoError(t, err)
	merged, err := left.Merge(right)
	require.NoError(t, err)
	got, _, err := merged.Apply()
	require.NoError(t, err)
	assert.Equal(t, "urn:example:a#f1", got.String())

	// replace vs delete stays a conflict.
	rp, err := urn.NewEditPlan(base, urn.ReplaceFragment("x"))
	require.NoError(t, err)
	dp, err := urn.NewEditPlan(base, urn.DeleteFragment())
	require.NoError(t, err)
	_, err = rp.Merge(dp)
	require.Error(t, err)
}

func TestEditPlanRegressionRebaseJSONRoundTrip(t *testing.T) {
	base := mustParse(t, "urn:example:a?+r1#f1", urn.RFC8141Only)
	plan, err := urn.NewEditPlan(base, urn.ReplaceNSS("mine"))
	require.NoError(t, err)
	latest := mustParse(t, "urn:example:a?+r9#f9", urn.RFC8141Only)
	rebased, err := plan.Rebase(latest)
	require.NoError(t, err)

	raw, err := json.Marshal(rebased)
	require.NoError(t, err)
	var restored urn.EditPlan
	require.NoError(t, json.Unmarshal(raw, &restored))
	assert.Equal(t, plan.OriginalText(), restored.OriginalText())
	assert.Equal(t, latest.String(), restored.BaselineText())
	got, d, err := restored.Apply()
	require.NoError(t, err)
	assert.Equal(t, "urn:example:mine?+r9#f9", got.String())
	assert.Equal(t, "r9", d.Changes[urn.ComponentR].New)
	assert.Equal(t, "f9", d.Changes[urn.ComponentFragment].New)
}

func TestEditPlanRegressionNilAndDuplicateRejection(t *testing.T) {
	_, err := urn.NewEditPlan(nil)
	require.Error(t, err)
	u := mustParse(t, "urn:example:a", urn.RFC2141Only)
	_, err = urn.NewEditPlan(u, urn.ReplaceNSS("x"), urn.ReplaceNSS("y"))
	require.Error(t, err)

	plan, err := urn.NewEditPlan(u, urn.ReplaceNSS("x"))
	require.NoError(t, err)
	_, err = plan.Merge(nil)
	require.Error(t, err)
	_, err = plan.Rebase(nil)
	require.Error(t, err)
}

func TestEditPlanRegressionInvalidLiterals(t *testing.T) {
	u := mustParse(t, "urn:example:a", urn.RFC8141Only)
	invalid := []string{
		"raw unicode \u00e9",
		"trailing percent %",
		"broken %2 escape",
		"%zz not hex",
		"has space",
		"/leading slash",
	}
	for _, v := range invalid {
		_, err := urn.NewEditPlan(u, urn.ReplaceRComponent(v))
		require.Error(t, err, v)
	}
	// 2141 nss rejects '~' and '&' (8141-only pchars).
	u2 := mustParse(t, "urn:example:a", urn.RFC2141Only)
	_, err := urn.NewEditPlan(u2, urn.ReplaceNSS("a~b"))
	require.Error(t, err)
	_, err = urn.NewEditPlan(u2, urn.ReplaceNSS("a&b"))
	require.Error(t, err)
}

func TestEditPlanRegressionConflictTamperRejected(t *testing.T) {
	base := mustParse(t, "urn:example:a?+r1", urn.RFC8141Only)
	left, err := urn.NewEditPlan(base, urn.ReplaceRComponent("L"))
	require.NoError(t, err)
	right, err := urn.NewEditPlan(base, urn.ReplaceRComponent("R"))
	require.NoError(t, err)
	merged, err := left.Merge(right)
	require.Error(t, err)

	raw, err := json.Marshal(merged)
	require.NoError(t, err)

	tamper := func(mut func(map[string]interface{})) {
		var head map[string]interface{}
		require.NoError(t, json.Unmarshal(raw, &head))
		mut(head)
		bad, mErr := json.Marshal(head)
		require.NoError(t, mErr)
		var p urn.EditPlan
		require.Error(t, json.Unmarshal(bad, &p))
	}
	tamper(func(h map[string]interface{}) {
		c := h["conflicts"].([]interface{})[0].(map[string]interface{})
		c["right"] = "TAMPERED"
	})
	tamper(func(h map[string]interface{}) {
		c := h["conflicts"].([]interface{})[0].(map[string]interface{})
		c["left"] = "TAMPERED"
	})
	tamper(func(h map[string]interface{}) {
		c := h["conflicts"].([]interface{})[0].(map[string]interface{})
		c["base"] = "TAMPERED"
	})
	tamper(func(h map[string]interface{}) {
		h["conflicts"] = []interface{}{}
	})
	tamper(func(h map[string]interface{}) {
		c := h["conflicts"].([]interface{})[0].(map[string]interface{})
		c["rightOp"] = "deleted"
	})
}

func TestEditPlanRegressionNormalizeEqualCompatible(t *testing.T) {
	original := "URN:EXAMPLE:A%2CB?+R"
	u := mustParse(t, original, urn.RFC8141Only)
	plan, err := urn.NewEditPlan(u, urn.ReplaceFragment("F"))
	require.NoError(t, err)
	got, _, err := plan.Apply()
	require.NoError(t, err)

	// Lexical equivalence ignores fragments just like before (existing behavior).
	assert.True(t, u.Equal(got))
	assert.Equal(t, "URN:EXAMPLE:A%2CB?+R#F", got.String())
	// Normalize preserves existing semantics: lowercase prefix/NID, non-hex
	// NSS letters unchanged, the hex token lowercased; 8141 components
	// dropped. After a parse-edit-string-parse the normalized form is derived
	// from the literal candidate spelling.
	norm := got.Normalize()
	assert.Equal(t, "urn:example:A%2cB", norm.String())
	// Baseline parsed once keeps its precomputed normalized spelling.
	assert.Equal(t, "urn:example:A%2cB", u.Normalize().String())
}
