package provider

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/pigeon-as/terraform-provider-gigahost/internal/client"
)

func mockZoneClient(t *testing.T, handler http.HandlerFunc) *client.Client {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	c, err := client.NewClient(&client.Config{
		Address: server.URL, Token: "test-token", HTTPClient: server.Client(),
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	return c
}

func zoneSet(items ...string) types.Set {
	values := make([]attr.Value, len(items))
	for i, item := range items {
		values[i] = types.StringValue(item)
	}
	return types.SetValueMust(types.StringType, values)
}

func TestDNSZoneSettingsSchema(t *testing.T) {
	r := &dnsZoneResource{}
	var schemaResp resource.SchemaResponse
	r.Schema(context.Background(), resource.SchemaRequest{}, &schemaResp)
	if diags := schemaResp.Schema.ValidateImplementation(context.Background()); diags.HasError() {
		t.Fatalf("invalid schema: %v", diags)
	}
	for _, field := range []string{"dnssec_enabled", "nameservers", "external_ds_records", "masters", "domain_status"} {
		if _, ok := schemaResp.Schema.Attributes[field]; !ok {
			t.Errorf("missing field %s", field)
		}
	}
	if _, exists := schemaResp.Schema.Attributes["auto_renew"]; exists {
		t.Fatal("auto_renew is intentionally out of scope")
	}
}

func TestDNSZoneSettingsApplyOrder(t *testing.T) {
	var requests []string
	c := mockZoneClient(t, func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodPut && req.Method != http.MethodPost {
			t.Errorf("unexpected method: %s", req.Method)
		}
		requests = append(requests, req.Method+" "+req.URL.Path)
		_, _ = io.WriteString(w, `{"meta":{"status":200},"data":[]}`)
	})
	r := &dnsZoneResource{client: c}
	ctx := context.Background()
	records, diags := types.SetValueFrom(ctx, externalDSRecordType(), []dsRecordModel{{
		KeyTag:     types.Int64Value(12345),
		Algorithm:  types.Int64Value(13),
		DigestType: types.Int64Value(2),
		Digest:     types.StringValue("1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF"),
		PublicKey:  types.StringNull(),
		KeyType:    types.Int64Null(),
	}})
	if diags.HasError() {
		t.Fatalf("encode DS records: %v", diags)
	}
	old := dnsZoneResourceModel{
		Nameservers:       zoneSet("ns1.old.net", "ns2.old.net"),
		DNSSECEnabled:     types.BoolValue(true),
		ExternalDSRecords: types.SetNull(externalDSRecordType()),
	}
	next := dnsZoneResourceModel{
		Nameservers:       zoneSet("ns1.external.net", "ns2.external.net"),
		DNSSECEnabled:     types.BoolValue(true),
		ExternalDSRecords: records,
	}
	if err := r.applyZoneSettings(ctx, "195", old, next); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"PUT /dns/zones/195/nameservers",
		"PUT /dns/zones/195/dnssec",
		"POST /dns/zones/195/ds-records/external",
	}
	if !reflect.DeepEqual(requests, want) {
		t.Fatalf("request order %v, want %v", requests, want)
	}
}

func TestDNSZoneSettingsUnmanaged(t *testing.T) {
	c := mockZoneClient(t, func(w http.ResponseWriter, req *http.Request) {
		t.Errorf("unmanaged settings must not call %s %s", req.Method, req.URL.Path)
	})
	r := &dnsZoneResource{client: c}
	empty := dnsZoneResourceModel{
		Nameservers:       types.SetNull(types.StringType),
		ExternalDSRecords: types.SetNull(externalDSRecordType()),
		DNSSECEnabled:     types.BoolNull(),
	}
	if err := r.applyZoneSettings(context.Background(), "195", empty, empty); err != nil {
		t.Fatal(err)
	}
}

func TestDNSZoneSettingsDrift(t *testing.T) {
	c := mockZoneClient(t, func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodGet || req.URL.Path != "/dns/zones" {
			t.Errorf("unexpected request: %s %s", req.Method, req.URL.Path)
		}
		_, _ = io.WriteString(w, `{"meta":{"status":200},"data":[{
			"zone_id":"195","zone_name":"example.no","zone_type":"NATIVE",
			"zone_is_registered":"1","domain_dnssec":"0",
			"nameservers":["ns1.external.net","ns2.external.net"]
		}]}`)
	})
	r := &dnsZoneResource{client: c}
	z, err := c.GetZone(context.Background(), "195")
	if err != nil {
		t.Fatal(err)
	}
	state := dnsZoneToModel(z)
	state.DNSSECEnabled = types.BoolValue(true)
	state.Nameservers = zoneSet("ns1.old.net", "ns2.old.net")
	if err := r.refreshZoneSettings(context.Background(), z, &state); err != nil {
		t.Fatal(err)
	}
	if !state.DNSSECEnabled.Equal(types.BoolValue(false)) {
		t.Fatalf("DNSSEC drift not detected: %v", state.DNSSECEnabled)
	}
	var nameservers []string
	diags := state.Nameservers.ElementsAs(context.Background(), &nameservers, false)
	if diags.HasError() || !sameZoneNameservers(nameservers, []string{"ns1.external.net", "ns2.external.net"}) {
		t.Fatalf("nameserver drift: %v (%v)", nameservers, diags)
	}
}

func TestDNSZoneSettingsMissingDSRecordsEnablement(t *testing.T) {
	r := &dnsZoneResource{}
	next := dnsZoneResourceModel{
		DNSSECEnabled:     types.BoolNull(),
		ExternalDSRecords: types.SetValueMust(externalDSRecordType(), []attr.Value{}),
	}
	if err := r.applyZoneSettings(context.Background(), "195", dnsZoneResourceModel{}, next); err == nil {
		t.Fatal("external DS records should require enabled DNSSEC")
	}
}
