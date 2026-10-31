package provider

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/setplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/pigeon-as/terraform-provider-gigahost/internal/client"
)

type dsRecordModel struct {
	KeyTag     types.Int64  `tfsdk:"key_tag"`
	Algorithm  types.Int64  `tfsdk:"algorithm"`
	DigestType types.Int64  `tfsdk:"digest_type"`
	Digest     types.String `tfsdk:"digest"`
	PublicKey  types.String `tfsdk:"public_key"`
	KeyType    types.Int64  `tfsdk:"key_type"`
}

func externalDSRecordType() types.ObjectType {
	return types.ObjectType{AttrTypes: map[string]attr.Type{
		"key_tag":     types.Int64Type,
		"algorithm":   types.Int64Type,
		"digest_type": types.Int64Type,
		"digest":      types.StringType,
		"public_key":  types.StringType,
		"key_type":    types.Int64Type,
	}}
}

func externalDSRecordSchema() schema.SetNestedAttribute {
	return schema.SetNestedAttribute{
		Optional: true,
		MarkdownDescription: "Registry DS records for an externally hosted registered domain. " +
			"Requires dnssec_enabled = true. Omit to leave unmanaged; disable DNSSEC to remove DS records.",
		Validators: []validator.Set{setvalidator.SizeAtLeast(1)},
		NestedObject: schema.NestedAttributeObject{Attributes: map[string]schema.Attribute{
			"key_tag": schema.Int64Attribute{
				Required:            true,
				MarkdownDescription: "DNSSEC key tag (0-65535).",
				Validators:          []validator.Int64{int64validator.Between(0, 65535)},
			},
			"algorithm": schema.Int64Attribute{
				Required:            true,
				MarkdownDescription: "DNSSEC signing algorithm.",
				Validators:          []validator.Int64{int64validator.OneOf(5, 7, 8, 10, 13, 14, 15, 16)},
			},
			"digest_type": schema.Int64Attribute{
				Required:            true,
				MarkdownDescription: "Digest type: 1 (SHA-1), 2 (SHA-256) or 4 (SHA-384).",
				Validators:          []validator.Int64{int64validator.OneOf(1, 2, 4)},
			},
			"digest": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Hexadecimal digest; Gigahost validates its length.",
				Validators:          []validator.String{stringvalidator.RegexMatches(regexp.MustCompile("^[0-9a-fA-F]+$"), "must be hexadecimal")},
			},
			"public_key": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Base64 DNSKEY public key; required for some TLDs (e.g. .be, .de, .eu, .nl).",
			},
			"key_type": schema.Int64Attribute{
				Optional:            true,
				MarkdownDescription: "DNSKEY flags: 257 (KSK) or 256 (ZSK); used with public_key.",
				Validators:          []validator.Int64{int64validator.OneOf(256, 257)},
			},
		}},
	}
}

func masterServersSchema() schema.SetAttribute {
	return schema.SetAttribute{
		Optional:    true,
		ElementType: types.StringType,
		MarkdownDescription: "Primary DNS server IPs for a SLAVE zone. Changing the masters replaces the zone. " +
			"This uses the secondary-zone creation API observed in the Gigahost panel (not publicly documented).",
		Validators:    []validator.Set{setvalidator.SizeAtLeast(1)},
		PlanModifiers: []planmodifier.Set{setplanmodifier.RequiresReplace()},
	}
}

func listZoneStrings(ctx context.Context, value types.Set) ([]string, error) {
	if value.IsNull() {
		return nil, nil
	}
	var values []string
	if diags := value.ElementsAs(ctx, &values, false); diags.HasError() {
		return nil, fmt.Errorf("decode set: %v", diags)
	}
	return values, nil
}

func sameZoneNameservers(a, b []string) bool {
	normalize := func(xs []string) map[string]bool {
		out := make(map[string]bool, len(xs))
		for _, x := range xs {
			out[strings.TrimSuffix(strings.ToLower(strings.TrimSpace(x)), ".")] = true
		}
		return out
	}
	left, right := normalize(a), normalize(b)
	if len(left) != len(right) {
		return false
	}
	for x := range left {
		if !right[x] {
			return false
		}
	}
	return true
}

func dsKeyType(keyType types.Int64) *int64 {
	if keyType.IsNull() || keyType.IsUnknown() {
		return nil
	}
	v := keyType.ValueInt64()
	return &v
}

// applyZoneSettings never touches registry settings absent from configuration.
// Nameservers precede DNSSEC because re-delegation can disable DNSSEC for .no.
func (r *dnsZoneResource) applyZoneSettings(ctx context.Context, zoneID string, old, next dnsZoneResourceModel) error {
	if !next.ExternalDSRecords.IsNull() && (next.DNSSECEnabled.IsNull() || !next.DNSSECEnabled.ValueBool()) {
		return fmt.Errorf("external_ds_records requires dnssec_enabled = true")
	}

	nameserversChanged := false
	if !next.Nameservers.IsNull() {
		desired, err := listZoneStrings(ctx, next.Nameservers)
		if err != nil {
			return fmt.Errorf("nameservers: %w", err)
		}
		existing, err := listZoneStrings(ctx, old.Nameservers)
		if err != nil {
			return fmt.Errorf("previous nameservers: %w", err)
		}
		if old.Nameservers.IsNull() || !sameZoneNameservers(desired, existing) {
			if err := r.client.UpdateNameservers(ctx, zoneID, desired); err != nil {
				return fmt.Errorf("update nameservers: %w", err)
			}
			nameserversChanged = true
		}
	}
	if !next.DNSSECEnabled.IsNull() &&
		(old.DNSSECEnabled.IsNull() || !old.DNSSECEnabled.Equal(next.DNSSECEnabled) ||
			(nameserversChanged && next.DNSSECEnabled.ValueBool())) {
		if err := r.client.SetDNSSEC(ctx, zoneID, next.DNSSECEnabled.ValueBool()); err != nil {
			return fmt.Errorf("update DNSSEC: %w", err)
		}
	}
	if !next.ExternalDSRecords.IsNull() &&
		(old.ExternalDSRecords.IsNull() || !old.ExternalDSRecords.Equal(next.ExternalDSRecords) || nameserversChanged) {
		var models []dsRecordModel
		if diags := next.ExternalDSRecords.ElementsAs(ctx, &models, false); diags.HasError() {
			return fmt.Errorf("decode external DS records: %v", diags)
		}
		records := make([]client.DSRecord, 0, len(models))
		for _, m := range models {
			records = append(records, client.DSRecord{
				KeyTag: m.KeyTag.ValueInt64(), Algorithm: m.Algorithm.ValueInt64(),
				DigestType: m.DigestType.ValueInt64(), Digest: m.Digest.ValueString(),
				PublicKey: m.PublicKey.ValueString(), KeyType: dsKeyType(m.KeyType),
			})
		}
		if err := r.client.SubmitExternalDSRecords(ctx, zoneID, records); err != nil {
			return fmt.Errorf("update external DS records: %w", err)
		}
	}
	return nil
}

// refreshZoneSettings updates only settings actively managed in the old state.
// This prevents imports of an existing zone from implicitly managing DNSSEC.
func (r *dnsZoneResource) refreshZoneSettings(ctx context.Context, z *client.DnsZone, state *dnsZoneResourceModel) error {
	zoneID := z.ZoneID
	if !state.Nameservers.IsNull() {
		observed := z.Nameservers
		if observed == nil {
			// Fallback for API versions not returning nameservers in GET /zones.
			var err error
			observed, err = r.client.ListApexNameservers(ctx, zoneID)
			if err != nil {
				return fmt.Errorf("read nameservers: %w", err)
			}
		}
		if len(observed) > 0 {
			desired, err := listZoneStrings(ctx, state.Nameservers)
			if err != nil {
				return err
			}
			if !sameZoneNameservers(desired, observed) {
				set, diags := types.SetValueFrom(ctx, types.StringType, observed)
				if diags.HasError() {
					return fmt.Errorf("decode observed nameservers: %v", diags)
				}
				state.Nameservers = set
			}
		}
	}
	if !state.Masters.IsNull() {
		masters := client.SplitMasters(z.ZoneMasters)
		if len(masters) > 0 {
			existing, err := listZoneStrings(ctx, state.Masters)
			if err != nil {
				return err
			}
			if !sameZoneNameservers(existing, masters) {
				set, diags := types.SetValueFrom(ctx, types.StringType, masters)
				if diags.HasError() {
					return fmt.Errorf("decode observed masters: %v", diags)
				}
				state.Masters = set
			}
		}
	}
	if !state.DNSSECEnabled.IsNull() {
		if z.DNSSEC != nil && !bool(*z.DNSSEC) {
			state.DNSSECEnabled = types.BoolValue(false)
			state.DNSSECDSRecords = types.StringNull()
		} else {
			ds, err := r.client.GetDSRecords(ctx, zoneID)
			switch {
			case errors.Is(err, client.ErrDNSSECNotEnabled):
				state.DNSSECEnabled = types.BoolValue(false)
				state.DNSSECDSRecords = types.StringNull()
			case err != nil:
				return fmt.Errorf("read DNSSEC: %w", err)
			default:
				state.DNSSECEnabled = types.BoolValue(true)
				state.DNSSECDSRecords = types.StringValue(ds)
			}
		}
	}
	if !state.ExternalDSRecords.IsNull() {
		records, err := r.client.GetExternalDSRecords(ctx, zoneID)
		if err != nil {
			return fmt.Errorf("read external DS records: %w", err)
		}
		var previouslyManaged []dsRecordModel
		if diags := state.ExternalDSRecords.ElementsAs(ctx, &previouslyManaged, false); diags.HasError() {
			return fmt.Errorf("decode previous DS records: %v", diags)
		}
		models := make([]dsRecordModel, 0, len(records))
		for _, d := range records {
			models = append(models, dsRecordModel{
				KeyTag:     types.Int64Value(d.KeyTag),
				Algorithm:  types.Int64Value(d.Algorithm),
				DigestType: types.Int64Value(d.DigestType),
				Digest:     types.StringValue(d.Digest),
				PublicKey:  types.StringNull(),
				KeyType:    types.Int64Null(),
			})
			if d.PublicKey != "" {
				models[len(models)-1].PublicKey = types.StringValue(d.PublicKey)
			}
			if d.KeyType != nil {
				models[len(models)-1].KeyType = types.Int64Value(*d.KeyType)
			}
			// Some registry read responses omit DNSKEY inputs. In that case preserve
			// the configured optional values for the matching DS tuple.
			for _, previous := range previouslyManaged {
				if previous.KeyTag.ValueInt64() != d.KeyTag ||
					previous.Algorithm.ValueInt64() != d.Algorithm ||
					previous.DigestType.ValueInt64() != d.DigestType ||
					!strings.EqualFold(previous.Digest.ValueString(), d.Digest) {
					continue
				}
				if d.PublicKey == "" {
					models[len(models)-1].PublicKey = previous.PublicKey
				}
				if d.KeyType == nil {
					models[len(models)-1].KeyType = previous.KeyType
				}
				break
			}
		}
		set, diags := types.SetValueFrom(ctx, externalDSRecordType(), models)
		if diags.HasError() {
			return fmt.Errorf("decode external DS records: %v", diags)
		}
		state.ExternalDSRecords = set
	}
	return nil
}

func copyZoneSettings(dst *dnsZoneResourceModel, source dnsZoneResourceModel) {
	dst.Nameservers = source.Nameservers
	dst.Masters = source.Masters
	dst.DNSSECEnabled = source.DNSSECEnabled
	dst.DNSSECDSRecords = source.DNSSECDSRecords
	dst.ExternalDSRecords = source.ExternalDSRecords
}
