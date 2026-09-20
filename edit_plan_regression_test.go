package urn

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	scimschema "github.com/leodido/go-urn/scim/schema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func parseMode(t *testing.T, input string, mode ParsingMode) *URN {
	t.Helper()
	u, ok := Parse([]byte(input), WithParsingMode(mode))
	require.True(t, ok, "parse %q in mode %d should succeed", input, mode)
	require.NotNil(t, u)
	return u
}

// TestEditPlanRegressionOptionalComponents covers preservation and deletion of
// existing non-empty optional components and their separators.
func TestEditPlanRegressionOptionalComponents(t *testing.T) {
	original := "URN:Foo:a123%2Cb?+Rcomp?=Qcomp#Frag"
	base := parseMode(t, original, RFC8141Only)

	t.Run("untouched components survive byte-for-byte", func(t *testing.T) {
		plan, err := NewEditPlan(base, RFC8141Only, ReplaceNSS("new%2Cnss"))
		require.NoError(t, err)
		got, diffs, err := plan.Apply()
		require.NoError(t, err)
		assert.Equal(t, "URN:Foo:new%2Cnss?+Rcomp?=Qcomp#Frag", got.String())
		assert.Equal(t, "Foo", got.ID)
		assert.Equal(t, "Rcomp", got.RComponent())
		assert.Equal(t, "Qcomp", got.QComponent())
		assert.Equal(t, "Frag", got.FComponent())
		require.Len(t, diffs, 1)
		assert.Equal(t, ComponentDiff{Component: ComponentNSS, From: "a123%2Cb", To: "new%2Cnss"}, diffs[0])
	})

	t.Run("delete r-component keeps separators of surviving components", func(t *testing.T) {
		plan, err := NewEditPlan(base, RFC8141Only, DeleteRComponent())
		require.NoError(t, err)
		got, diffs, err := plan.Apply()
		require.NoError(t, err)
		assert.Equal(t, "URN:Foo:a123%2Cb?=Qcomp#Frag", got.String())
		assert.Empty(t, got.RComponent())
		assert.Equal(t, "Qcomp", got.QComponent())
		assert.Equal(t, "Frag", got.FComponent())
		assert.Equal(t, []ComponentDiff{{Component: ComponentRComponent, From: "Rcomp", To: ""}}, diffs)
	})

	t.Run("delete q-component keeps r and fragment separators", func(t *testing.T) {
		plan, err := NewEditPlan(base, RFC8141Only, DeleteQComponent())
		require.NoError(t, err)
		got, _, err := plan.Apply()
		require.NoError(t, err)
		assert.Equal(t, "URN:Foo:a123%2Cb?+Rcomp#Frag", got.String())
	})

	t.Run("delete fragment keeps the resolution parameters", func(t *testing.T) {
		plan, err := NewEditPlan(base, RFC8141Only, DeleteFragment())
		require.NoError(t, err)
		got, _, err := plan.Apply()
		require.NoError(t, err)
		assert.Equal(t, "URN:Foo:a123%2Cb?+Rcomp?=Qcomp", got.String())
		assert.Empty(t, got.FComponent())
	})

	t.Run("replacing an absent component adds it with the right separator", func(t *testing.T) {
		plain := parseMode(t, "urn:example:nss", RFC8141Only)
		plan, err := NewEditPlan(plain, RFC8141Only, ReplaceRComponent("r"), ReplaceFragment("f"))
		require.NoError(t, err)
		got, diffs, err := plan.Apply()
		require.NoError(t, err)
		assert.Equal(t, "urn:example:nss?+r#f", got.String())
		assert.ElementsMatch(t,
			[]ComponentDiff{
				{Component: ComponentRComponent, From: "", To: "r"},
				{Component: ComponentFragment, From: "", To: "f"},
			}, diffs)
	})

	t.Run("old URN is not mutated by apply", func(t *testing.T) {
		plan, err := NewEditPlan(base, RFC8141Only, DeleteRComponent(), ReplaceQComponent("other"))
		require.NoError(t, err)
		_, _, err = plan.Apply()
		require.NoError(t, err)
		assert.Equal(t, original, base.String())
		assert.Equal(t, "Rcomp", base.RComponent())
		assert.Equal(t, "Qcomp", base.QComponent())
	})
}

// TestEditPlanRegressionEmptyRQ rejects empty r/q components: they cannot be
// distinguished from absent components after re-parsing.
func TestEditPlanRegressionEmptyRQ(t *testing.T) {
	base := parseMode(t, "urn:example:nss?+r?=q#f", RFC8141Only)
	for _, edit := range []Edit{ReplaceRComponent(""), ReplaceQComponent("")} {
		_, err := NewEditPlan(base, RFC8141Only, edit)
		require.Error(t, err, "edit %s must be rejected", edit)
		assert.True(t, errors.Is(err, ErrInvalidComponent), "edit %s: %v", edit, err)
	}
	_, err := NewEditPlan(base, RFC8141Only, ReplaceFragment(""))
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidComponent))

	// Deleting components that are already absent is harmless (no-op intention).
	plain := parseMode(t, "urn:example:nss", RFC8141Only)
	plan, err := NewEditPlan(plain, RFC8141Only, DeleteRComponent(), DeleteQComponent(), DeleteFragment())
	require.NoError(t, err)
	got, diffs, err := plan.Apply()
	require.NoError(t, err)
	assert.Equal(t, "urn:example:nss", got.String())
	assert.Empty(t, diffs)
}

// TestEditPlanRegressionPercentCase keeps %2C vs %2c and URN/NID casing
// byte-for-byte on untouched fragments, while replacements keep their own case.
func TestEditPlanRegressionPercentCase(t *testing.T) {
	original := "URN:Foo:a123%2Cb?+R%2c?=Q%2C#F%2c"
	base := parseMode(t, original, RFC8141Only)

	plan, err := NewEditPlan(base, RFC8141Only, ReplaceNSS("z%2CZ"))
	require.NoError(t, err)
	got, _, err := plan.Apply()
	require.NoError(t, err)
	assert.Equal(t, "URN:Foo:z%2CZ?+R%2c?=Q%2C#F%2c", got.String())

	// Round-trip via JSON keeps the same candidate text.
	data, err := json.Marshal(plan)
	require.NoError(t, err)
	var restored EditPlan
	require.NoError(t, json.Unmarshal(data, &restored))
	got2, _, err := restored.Apply()
	require.NoError(t, err)
	assert.Equal(t, "URN:Foo:z%2CZ?+R%2c?=Q%2C#F%2c", got2.String())

	// The original baseline object stays untouched.
	assert.Equal(t, original, base.String())

	// Lexical equivalence does not authorize rewriting: replacing NID with a
	// different case literal keeps that literal exactly.
	plan2, err := NewEditPlan(base, RFC8141Only, ReplaceNID("FOO"))
	require.NoError(t, err)
	got3, _, err := plan2.Apply()
	require.NoError(t, err)
	assert.Equal(t, "URN:FOO:a123%2Cb?+R%2c?=Q%2C#F%2c", got3.String())
}

// TestEditPlanRegressionEncodedSeparators accepts encoded ? and # but rejects
// their unencoded separator-mimicking forms.
func TestEditPlanRegressionEncodedSeparators(t *testing.T) {
	base := parseMode(t, "urn:example:nss", RFC8141Only)

	plan, err := NewEditPlan(base, RFC8141Only,
		ReplaceNSS("a%3Fb%23c"),
		ReplaceRComponent("r%3F=%23"),
		ReplaceQComponent("q%3D%2B%23"),
		ReplaceFragment("fr%23ag?+kept%3D"))
	require.NoError(t, err)
	got, _, err := plan.Apply()
	require.NoError(t, err)
	assert.Equal(t, "urn:example:a%3Fb%23c?+r%3F=%23?=q%3D%2B%23#fr%23ag?+kept%3D", got.String())

	for _, edit := range []Edit{
		ReplaceRComponent("r?=q"),
		ReplaceRComponent("r?+x"),
		ReplaceQComponent("q?=x"),
		ReplaceRComponent("r#f"),
		ReplaceFragment("a#b"),
		ReplaceNSS("a?+b"),
	} {
		_, err := NewEditPlan(base, RFC8141Only, edit)
		require.Error(t, err, "edit %s must be rejected", edit)
	}
}

// TestEditPlanRegressionSCIMView ensures the public SCIM view is rebuilt from
// the new NSS after an edit; the parsed baseline keeps its original view.
func TestEditPlanRegressionSCIMView(t *testing.T) {
	original := "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	base := parseMode(t, original, RFC7643Only)
	require.True(t, base.IsSCIM())
	require.Equal(t, scimschema.API, base.SCIM().Type)
	require.Equal(t, "messages", base.SCIM().Name)
	require.Equal(t, "2.0:ListResponse", base.SCIM().Other)

	plan, err := NewEditPlan(base, RFC7643Only, ReplaceNSS("schemas:core:enterprise:User"))
	require.NoError(t, err)
	got, diffs, err := plan.Apply()
	require.NoError(t, err)
	assert.Equal(t, "urn:ietf:params:scim:schemas:core:enterprise:User", got.String())
	require.True(t, got.IsSCIM())
	view := got.SCIM()
	assert.Equal(t, scimschema.Schemas, view.Type)
	assert.Equal(t, "core", view.Name)
	assert.Equal(t, "enterprise:User", view.Other)
	assert.Equal(t, "urn:ietf:params:scim:schemas:core:enterprise:User", view.String())
	assert.Equal(t, []ComponentDiff{{
		Component: ComponentNSS,
		From:      "api:messages:2.0:ListResponse",
		To:        "schemas:core:enterprise:User",
	}}, diffs)

	// Stale cached view must not survive on the new object.
	assert.NotSame(t, base.SCIM(), got.SCIM())
	assert.Equal(t, "messages", base.SCIM().Name)

	// A SCIM NSS cannot gain RFC 8141-only components.
	_, err = NewEditPlan(base, RFC7643Only, ReplaceRComponent("x"))
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidEditPlan))
	_, err = NewEditPlan(base, RFC7643Only, ReplaceNSS("schemas:core:a/b"))
	require.Error(t, err)
}

// TestEditPlanRegressionJSONTampering rejects tampered fingerprints, mode
// switches, unknown components, duplicate keys and mixed edit intentions.
func TestEditPlanRegressionJSONTampering(t *testing.T) {
	base := parseMode(t, "urn:example:nss?+r", RFC8141Only)
	plan, err := NewEditPlan(base, RFC8141Only, ReplaceNSS("new"), DeleteRComponent())
	require.NoError(t, err)
	data, err := json.Marshal(plan)
	require.NoError(t, err)

	roundtrip := func(t *testing.T, raw string) {
		t.Helper()
		var got EditPlan
		err := json.Unmarshal([]byte(raw), &got)
		require.Error(t, err, "raw: %s", raw)
		assert.True(t, errors.Is(err, ErrInvalidEditPlan), "raw: %s err: %v", raw, err)
	}

	t.Run("roundtrip keeps all three intentions", func(t *testing.T) {
		var got EditPlan
		require.NoError(t, json.Unmarshal(data, &got))
		assert.Equal(t, plan.OriginalText(), got.OriginalText())
		assert.Equal(t, plan.Mode(), got.Mode())
		assert.Equal(t, plan.Fingerprint(), got.Fingerprint())
		r, hasR := got.Edit(ComponentRComponent)
		require.True(t, hasR)
		assert.Equal(t, actionDelete, r.action)
		n, hasN := got.Edit(ComponentNSS)
		require.True(t, hasN)
		assert.Equal(t, actionReplace, n.action)
		assert.Equal(t, "new", n.value)
		_, hasF := got.Edit(ComponentFragment)
		assert.False(t, hasF)
		applied, _, err := got.Apply()
		require.NoError(t, err)
		assert.Equal(t, "urn:example:new", applied.String())
	})

	t.Run("tampered fingerprint", func(t *testing.T) {
		roundtrip(t, strings.Replace(string(data), `"fingerprint":"`, `"fingerprint":"deadbeef`, 1))
	})
	t.Run("tampered original text", func(t *testing.T) {
		roundtrip(t, strings.Replace(string(data), `"urn:example:nss?+r"`, `"urn:example:tampered?+r"`, 1))
	})
	t.Run("mode switched", func(t *testing.T) {
		roundtrip(t, strings.Replace(string(data), `"mode":"rfc8141"`, `"mode":"rfc2141"`, 1))
	})
	t.Run("unknown component", func(t *testing.T) {
		roundtrip(t, strings.Replace(string(data), `"nss":`, `"unknown":{"action":"replace","value":"x"},"nss":`, 1))
	})
	t.Run("duplicate top-level key", func(t *testing.T) {
		raw := strings.TrimSuffix(string(data), "}") + `,"mode":"rfc2141"}`
		roundtrip(t, raw)
	})
	t.Run("duplicate edit key", func(t *testing.T) {
		raw := strings.Replace(string(data), `"nss":{"action":"replace","value":"new"}`,
			`"nss":{"action":"replace","value":"new"},"nss":{"action":"delete"}`, 1)
		roundtrip(t, raw)
	})
	t.Run("duplicate action key", func(t *testing.T) {
		raw := strings.Replace(string(data), `"action":"replace","value":"new"`,
			`"action":"replace","action":"delete","value":"new"`, 1)
		roundtrip(t, raw)
	})
	t.Run("delete carrying a value", func(t *testing.T) {
		roundtrip(t, strings.Replace(string(data), `{"action":"delete"}`, `{"action":"delete","value":"x"}`, 1))
	})
	t.Run("replace missing value", func(t *testing.T) {
		roundtrip(t, strings.Replace(string(data), `{"action":"replace","value":"new"}`, `{"action":"replace"}`, 1))
	})
	t.Run("unknown action", func(t *testing.T) {
		roundtrip(t, strings.Replace(string(data), `{"action":"replace","value":"new"}`, `{"action":"upsert","value":"new"}`, 1))
	})
}

// TestEditPlanRegressionMultipleConflicts verifies all same-component edits are
// reported at once with raw base/left/right literals, and conflicted plans
// refuse to apply.
func TestEditPlanRegressionMultipleConflicts(t *testing.T) {
	base := parseMode(t, "urn:example:a?+r?=q#f", RFC8141Only)
	left, err := NewEditPlan(base, RFC8141Only,
		ReplaceNID("leftnid"),
		ReplaceNSS("leftnss"),
		ReplaceRComponent("lr"),
		ReplaceFragment("lf"),
		ReplaceQComponent("lq"))
	require.NoError(t, err)
	right, err := NewEditPlan(base, RFC8141Only,
		ReplaceNID("rightnid"),
		ReplaceNSS("rightnss"),
		DeleteRComponent(),
		ReplaceFragment("rf"))
	require.NoError(t, err)

	merged, err := left.Merge(right)
	require.NoError(t, err)
	conflicts := merged.Conflicts()
	require.Len(t, conflicts, 4)
	assert.Equal(t,
		[]string{ComponentNID, ComponentNSS, ComponentRComponent, ComponentFragment},
		[]string{conflicts[0].Component, conflicts[1].Component, conflicts[2].Component, conflicts[3].Component})
	// q-component was edited by one side only: carried without a conflict.
	q, ok := merged.Edit(ComponentQComponent)
	require.True(t, ok)
	assert.Equal(t, "lq", q.value)
	for _, c := range conflicts {
		switch c.Component {
		case ComponentNID:
			assert.Equal(t, "example", *c.Base)
			assert.Equal(t, "leftnid", *c.Left)
			assert.Equal(t, "rightnid", *c.Right)
		case ComponentNSS:
			assert.Equal(t, "a", *c.Base)
			assert.Equal(t, "leftnss", *c.Left)
			assert.Equal(t, "rightnss", *c.Right)
		case ComponentRComponent:
			assert.Equal(t, "r", *c.Base)
			assert.Equal(t, "lr", *c.Left)
			assert.Nil(t, c.Right)
		case ComponentFragment:
			assert.Equal(t, "f", *c.Base)
			assert.Equal(t, "lf", *c.Left)
			assert.Equal(t, "rf", *c.Right)
		}
	}
	_, _, err = merged.Apply()
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrPlanConflict))
	_, err = json.Marshal(merged)
	require.Error(t, err)

	// Equivalent candidates are still conflicts: no automatic literal choice.
	eqA, err := NewEditPlan(base, RFC8141Only, ReplaceNSS("a%2c"))
	require.NoError(t, err)
	eqB, err := NewEditPlan(base, RFC8141Only, ReplaceNSS("a%2C"))
	require.NoError(t, err)
	eqMerged, err := eqA.Merge(eqB)
	require.NoError(t, err)
	require.Len(t, eqMerged.Conflicts(), 1)
}

// TestEditPlanRegressionMergeOrder proves disjoint-component merges converge
// on the same URN regardless of merge order.
func TestEditPlanRegressionMergeOrder(t *testing.T) {
	base := parseMode(t, "urn:example:a?+r?=q#f", RFC8141Only)
	a, err := NewEditPlan(base, RFC8141Only, ReplaceNID("nid-a"), ReplaceRComponent("ra"))
	require.NoError(t, err)
	b, err := NewEditPlan(base, RFC8141Only, ReplaceNSS("nss-b"), DeleteQComponent())
	require.NoError(t, err)
	c, err := NewEditPlan(base, RFC8141Only, ReplaceFragment("fc"))
	require.NoError(t, err)

	m1, err := a.Merge(b)
	require.NoError(t, err)
	m1, err = m1.Merge(c)
	require.NoError(t, err)

	m2, err := c.Merge(a)
	require.NoError(t, err)
	m2, err = m2.Merge(b)
	require.NoError(t, err)

	m3, err := b.Merge(c)
	require.NoError(t, err)
	m3, err = m3.Merge(a)
	require.NoError(t, err)

	assert.Nil(t, m1.Conflicts())
	u1, _, err := m1.Apply()
	require.NoError(t, err)
	u2, _, err := m2.Apply()
	require.NoError(t, err)
	u3, _, err := m3.Apply()
	require.NoError(t, err)
	want := "urn:nid-a:nss-b?+ra#fc"
	assert.Equal(t, want, u1.String())
	assert.Equal(t, want, u2.String())
	assert.Equal(t, want, u3.String())

	// Merge preserves baseline fingerprint and original text.
	assert.Equal(t, a.Fingerprint(), m1.Fingerprint())
	assert.Equal(t, base.String(), m1.OriginalText())

	// Different baselines cannot merge.
	other := parseMode(t, "urn:example:other", RFC8141Only)
	o, err := NewEditPlan(other, RFC8141Only, ReplaceFragment("x"))
	require.NoError(t, err)
	_, err = a.Merge(o)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrBaselineMismatch))

	// Different modes cannot merge even on equal text when r/q components exist.
	s2141 := parseMode(t, "urn:example:a", RFC2141Only)
	s8141 := parseMode(t, "urn:example:a", RFC8141Only)
	p2141, err := NewEditPlan(s2141, RFC2141Only, ReplaceNSS("b"))
	require.NoError(t, err)
	p8141, err := NewEditPlan(s8141, RFC8141Only, ReplaceFragment("g"))
	require.NoError(t, err)
	_, err = p2141.Merge(p8141)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrBaselineMismatch))
}

// TestEditPlanRegressionStaleRebase covers component-level rebase: untouched
// components carry the latest value; jointly touched components conflict even
// when the whole URNs stay lexically equivalent.
func TestEditPlanRegressionStaleRebase(t *testing.T) {
	t.Run("latest only changes untouched components", func(t *testing.T) {
		base := parseMode(t, "urn:example:a?+r?=q#f", RFC8141Only)
		plan, err := NewEditPlan(base, RFC8141Only, ReplaceNSS("mine"))
		require.NoError(t, err)
		latest := parseMode(t, "urn:example:a?+r2?=q2#f2", RFC8141Only)

		rebased, err := plan.Rebase(latest)
		require.NoError(t, err)
		assert.Nil(t, rebased.Conflicts())
		assert.Equal(t, latest.String(), rebased.OriginalText())
		assert.Equal(t, computeFingerprint(RFC8141Only, latest.String()), rebased.Fingerprint())
		got, _, err := rebased.Apply()
		require.NoError(t, err)
		assert.Equal(t, "urn:example:mine?+r2?=q2#f2", got.String())
	})

	t.Run("latest adds a component the plan never touched", func(t *testing.T) {
		base := parseMode(t, "urn:example:a", RFC8141Only)
		plan, err := NewEditPlan(base, RFC8141Only, ReplaceNSS("mine"))
		require.NoError(t, err)
		latest := parseMode(t, "urn:example:a#newfrag", RFC8141Only)
		rebased, err := plan.Rebase(latest)
		require.NoError(t, err)
		got, _, err := rebased.Apply()
		require.NoError(t, err)
		assert.Equal(t, "urn:example:mine#newfrag", got.String())
	})

	t.Run("same component on both sides conflicts", func(t *testing.T) {
		base := parseMode(t, "urn:example:a?+r", RFC8141Only)
		plan, err := NewEditPlan(base, RFC8141Only, ReplaceNSS("mine"), ReplaceRComponent("pr"))
		require.NoError(t, err)
		latest := parseMode(t, "urn:example:theirs?+lr", RFC8141Only)
		rebased, err := plan.Rebase(latest)
		require.NoError(t, err)
		conflicts := rebased.Conflicts()
		require.Len(t, conflicts, 2)
		assert.Equal(t, ComponentNSS, conflicts[0].Component)
		assert.Equal(t, "a", *conflicts[0].Base)
		assert.Equal(t, "mine", *conflicts[0].Left)
		assert.Equal(t, "theirs", *conflicts[0].Right)
		assert.Equal(t, ComponentRComponent, conflicts[1].Component)
		assert.Equal(t, "r", *conflicts[1].Base)
		assert.Equal(t, "pr", *conflicts[1].Left)
		assert.Equal(t, "lr", *conflicts[1].Right)
		_, _, err = rebased.Apply()
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrPlanConflict))
	})

	t.Run("lexical equivalence does not hide a rebase conflict", func(t *testing.T) {
		base := parseMode(t, "urn:example:a%2Cb", RFC8141Only)
		plan, err := NewEditPlan(base, RFC8141Only, ReplaceNSS("a%2Cb"))
		require.NoError(t, err)
		latest := parseMode(t, "URN:EXAMPLE:a%2cb", RFC8141Only)
		require.True(t, base.Equal(latest), "fixture URNs must be lexically equivalent")
		rebased, err := plan.Rebase(latest)
		require.NoError(t, err)
		require.Len(t, rebased.Conflicts(), 1)
		c := rebased.Conflicts()[0]
		assert.Equal(t, ComponentNSS, c.Component)
		assert.Equal(t, "a%2Cb", *c.Left)
		assert.Equal(t, "a%2cb", *c.Right)
	})

	t.Run("mode mismatch on latest is rejected", func(t *testing.T) {
		base := parseMode(t, "urn:example:a", RFC8141Only)
		plan, err := NewEditPlan(base, RFC8141Only, ReplaceNSS("b"))
		require.NoError(t, err)
		latest2141 := parseMode(t, "urn:example:a", RFC2141Only)
		_, err = plan.Rebase(latest2141)
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrBaselineMismatch))
	})

	t.Run("unchanged latest yields an equivalent plan", func(t *testing.T) {
		base := parseMode(t, "urn:example:a?+r", RFC8141Only)
		plan, err := NewEditPlan(base, RFC8141Only, DeleteRComponent())
		require.NoError(t, err)
		rebased, err := plan.Rebase(base)
		require.NoError(t, err)
		got, _, err := rebased.Apply()
		require.NoError(t, err)
		assert.Equal(t, "urn:example:a", got.String())
	})
}

// TestEditPlanRegressionInvalidLiterals covers raw Unicode, malformed percent
// escapes and separator characters delivered as component replacements.
func TestEditPlanRegressionInvalidLiterals(t *testing.T) {
	base2141 := parseMode(t, "urn:example:a", RFC2141Only)
	base8141 := parseMode(t, "urn:example:a?+r?=q#f", RFC8141Only)

	invalid2141 := []Edit{
		ReplaceNSS("café"),
		ReplaceNSS("a%2"),
		ReplaceNSS("a%zz"),
		ReplaceNSS("a?b"),
		ReplaceNID(""),
		ReplaceNID("bad nid"),
	}
	for _, edit := range invalid2141 {
		_, err := NewEditPlan(base2141, RFC2141Only, edit)
		require.Error(t, err, "edit %s must be rejected", edit)
	}
	invalid8141 := []Edit{
		ReplaceRComponent("%2"),
		ReplaceQComponent("%GG"),
		ReplaceRComponent("/leadingslash"),
		ReplaceQComponent("?leadingq"),
		ReplaceNSS("/leadingslash"),
		ReplaceFragment("hash#inside"),
	}
	for _, edit := range invalid8141 {
		_, err := NewEditPlan(base8141, RFC8141Only, edit)
		require.Error(t, err, "edit %s must be rejected", edit)
	}

	// RFC 2141 and SCIM modes never gain 8141-only components.
	scimBase := parseMode(t, "urn:ietf:params:scim:schemas:core", RFC7643Only)
	for _, edit := range []Edit{ReplaceRComponent("r"), ReplaceQComponent("q"), ReplaceFragment("g"),
		DeleteRComponent(), DeleteQComponent(), DeleteFragment()} {
		_, err := NewEditPlan(scimBase, RFC7643Only, edit)
		require.Error(t, err, "edit %s must be rejected in SCIM mode", edit)
	}

	// Duplicate intentions for the same component are rejected at build time.
	_, err := NewEditPlan(base8141, RFC8141Only, ReplaceRComponent("x"), DeleteRComponent())
	require.Error(t, err)
	_, err = NewEditPlan(base8141, RFC8141Only, ReplaceFragment("x"), ReplaceFragment("y"))
	require.Error(t, err)
}

// TestEditPlanRegressionApplyFailureAtomic ensures an invalid candidate never
// produces a partial result or mutates the baseline.
func TestEditPlanRegressionApplyFailureAtomic(t *testing.T) {
	original := "urn:example:a?+r"
	base := parseMode(t, original, RFC8141Only)

	// Build a valid plan over a structurally legal literal, then force the
	// candidate to break by tampering with the stored original text directly:
	// re-parsing the baseline must fail and Apply must return no URN.
	plan, err := NewEditPlan(base, RFC8141Only, ReplaceRComponent("rr"))
	require.NoError(t, err)
	plan.original = "urn:not:a:valid?8141"
	got, diffs, err := plan.Apply()
	require.Error(t, err)
	assert.Nil(t, got)
	assert.Nil(t, diffs)

	// The parsed baseline remains the original value.
	assert.Equal(t, original, base.String())
	assert.Equal(t, "r", base.RComponent())
}

// TestEditPlanRegressionModeSemantics ensures parse-edit-string-parse keeps
// component semantics aligned with the parsing mode, and Normalize/Equal/String
// behavior is unchanged on the produced URNs.
func TestEditPlanRegressionModeSemantics(t *testing.T) {
	t.Run("rfc2141 output behaves like a 2141 URN", func(t *testing.T) {
		base := parseMode(t, "URN:Example:a%2Cb", RFC2141Only)
		plan, err := NewEditPlan(base, RFC2141Only, ReplaceNSS("c%2Cd"))
		require.NoError(t, err)
		got, _, err := plan.Apply()
		require.NoError(t, err)
		assert.Equal(t, RFC2141, got.RFC())
		assert.False(t, got.IsSCIM())
		assert.Equal(t, "URN:Example:c%2Cd", got.String())
		assert.Equal(t, "urn:example:c%2cd", got.Normalize().String())
		other := parseMode(t, "urn:example:c%2cd", RFC2141Only)
		assert.True(t, got.Equal(other))
	})

	t.Run("rfc8141 output carries r/q/f semantics", func(t *testing.T) {
		base := parseMode(t, "urn:example:a", RFC8141Only)
		plan, err := NewEditPlan(base, RFC8141Only,
			ReplaceRComponent("rr"), ReplaceQComponent("qq"), ReplaceFragment("ff"))
		require.NoError(t, err)
		got, _, err := plan.Apply()
		require.NoError(t, err)
		assert.Equal(t, RFC8141, got.RFC())
		assert.Equal(t, "urn:example:a?+rr?=qq#ff", got.String())
		var marshaled URN8141
		data, err := json.Marshal(URN8141{URN: got})
		require.NoError(t, err)
		require.NoError(t, json.Unmarshal(data, &marshaled))
		assert.Equal(t, got.String(), marshaled.String())
	})

	t.Run("plan fingerprint is stable and mode-scoped", func(t *testing.T) {
		input := "urn:example:a"
		u2141 := parseMode(t, input, RFC2141Only)
		u8141 := parseMode(t, input, RFC8141Only)
		p2141, err := NewEditPlan(u2141, RFC2141Only)
		require.NoError(t, err)
		p8141, err := NewEditPlan(u8141, RFC8141Only)
		require.NoError(t, err)
		assert.NotEqual(t, p2141.Fingerprint(), p8141.Fingerprint())
		assert.Len(t, p2141.Fingerprint(), 64)
		// Same construction reproduces the same fingerprint.
		p2141Again, err := NewEditPlan(u2141, RFC2141Only)
		require.NoError(t, err)
		assert.Equal(t, p2141.Fingerprint(), p2141Again.Fingerprint())
	})
}

// TestEditPlanRegressionJSONRoundTrip persists plans across modes and every
// intention, and replays them identically after deserialization.
func TestEditPlanRegressionJSONRoundTrip(t *testing.T) {
	base := parseMode(t, "URN:Foo:a%2Cb?+R?=Q#F", RFC8141Only)
	plan, err := NewEditPlan(base, RFC8141Only,
		ReplaceNSS("n"),
		ReplaceQComponent("newq"),
		DeleteRComponent(),
		DeleteFragment())
	require.NoError(t, err)
	data, err := json.Marshal(plan)
	require.NoError(t, err)
	require.True(t, json.Valid(data))
	var restored EditPlan
	require.NoError(t, json.Unmarshal(data, &restored))
	u1, d1, err := plan.Apply()
	require.NoError(t, err)
	u2, d2, err := restored.Apply()
	require.NoError(t, err)
	assert.Equal(t, u1.String(), u2.String())
	assert.Equal(t, "URN:Foo:n?=newq", u2.String())
	assert.Equal(t, d1, d2)
	assert.Equal(t, plan.Fingerprint(), restored.Fingerprint())

	// SCIM mode round-trips too.
	scimBase := parseMode(t, "urn:ietf:params:scim:schemas:core", RFC7643Only)
	sp, err := NewEditPlan(scimBase, RFC7643Only, ReplaceNSS("api:messages:2.0:ListResponse"))
	require.NoError(t, err)
	sdata, err := json.Marshal(sp)
	require.NoError(t, err)
	require.Contains(t, string(sdata), `"mode":"scim"`)
	var sp2 EditPlan
	require.NoError(t, json.Unmarshal(sdata, &sp2))
	su, _, err := sp2.Apply()
	require.NoError(t, err)
	assert.Equal(t, "urn:ietf:params:scim:api:messages:2.0:ListResponse", su.String())
	require.NotNil(t, su.SCIM())
	assert.Equal(t, fmt.Sprintf("%s", scimschema.API), su.SCIM().Type.String())
}
