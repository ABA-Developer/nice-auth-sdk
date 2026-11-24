package verify

import (
	"encoding/json"
	"testing"
)

func TestClaimsExposeTheActorOfAnExchangedToken(t *testing.T) {
	var c Claims
	if err := json.Unmarshal([]byte(`{"sub":"usr_1","act":{"sub":"naia-backend"},"perms":["nadi.reports.read"]}`), &c); err != nil {
		t.Fatal(err)
	}
	if c.Subject != "usr_1" || c.Actor != "naia-backend" || !c.Has("nadi.reports.read") {
		t.Fatalf("claims %+v", c)
	}
	var plain Claims
	if err := json.Unmarshal([]byte(`{"sub":"usr_1"}`), &plain); err != nil || plain.Actor != "" {
		t.Fatalf("a token without act has no actor: %+v %v", plain, err)
	}
	if err := json.Unmarshal([]byte(`{"sub":"usr_1","act":"naia"}`), &plain); err == nil {
		t.Fatal("an act that is not an object is malformed")
	}
}

func TestClaimsExposeActAs(t *testing.T) {
	var c Claims
	if err := json.Unmarshal([]byte(`{"sub":"usr_1","nice_org_id":"org_c","nice_act_as":"org_p"}`), &c); err != nil {
		t.Fatal(err)
	}
	if !c.IsActAs() || c.ActAs != "org_p" || c.OrgID != "org_c" {
		t.Fatalf("claims %+v", c)
	}
	var plain Claims
	if err := json.Unmarshal([]byte(`{"sub":"usr_1"}`), &plain); err != nil || plain.IsActAs() {
		t.Fatalf("a token without nice_act_as is not act-as: %+v %v", plain, err)
	}
}

func TestClaimsExposeThePermissionReference(t *testing.T) {
	var c Claims
	if err := json.Unmarshal([]byte(`{"sub":"usr_1","perms_ref":"v1.abc"}`), &c); err != nil {
		t.Fatal(err)
	}
	if c.PermsRef != "v1.abc" || c.Permissions != nil {
		t.Fatalf("claims %+v", c)
	}
	var plain Claims
	if err := json.Unmarshal([]byte(`{"sub":"usr_1","perms":[]}`), &plain); err != nil || plain.PermsRef != "" {
		t.Fatalf("a token with perms has no reference: %+v %v", plain, err)
	}
}
