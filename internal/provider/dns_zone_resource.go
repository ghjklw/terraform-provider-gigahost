package provider

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/boolplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/pigeon-as/terraform-provider-gigahost/internal/client"
)

var (
	_ resource.Resource                = &dnsZoneResource{}
	_ resource.ResourceWithConfigure   = &dnsZoneResource{}
	_ resource.ResourceWithImportState = &dnsZoneResource{}
)

func NewDNSZoneResource() resource.Resource {
	return &dnsZoneResource{}
}

type dnsZoneResource struct {
	client *client.Client
}

type dnsZoneResourceModel struct {
	ExternalDns       types.Bool   `tfsdk:"external_dns"`
	ZoneActive        types.Bool   `tfsdk:"zone_active"`
	ZoneId            types.String `tfsdk:"zone_id"`
	ZoneName          types.String `tfsdk:"zone_name"`
	ZoneProtected     types.Bool   `tfsdk:"zone_protected"`
	ZoneType          types.String `tfsdk:"zone_type"`
	Registered        types.Bool   `tfsdk:"registered"`
	Status            types.String `tfsdk:"domain_status"`
	ExpiryDate        types.String `tfsdk:"domain_expiry_date"`
	Masters           types.Set    `tfsdk:"masters"`
	Nameservers       types.Set    `tfsdk:"nameservers"`
	DNSSECEnabled     types.Bool   `tfsdk:"dnssec_enabled"`
	DNSSECDSRecords   types.String `tfsdk:"dnssec_ds_records"`
	ExternalDSRecords types.Set    `tfsdk:"external_ds_records"`
}

func (r *dnsZoneResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_dns_zone"
}

func (r *dnsZoneResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages a DNS zone on the Gigahost account. " +
			"Registered-domain settings are optional and only apply if configured; for an existing registered domain, import the zone before configuring DNSSEC or delegation. " +
			"SLAVE zones can be created with the masters attribute.",
		Attributes: map[string]schema.Attribute{
			"external_dns": schema.BoolAttribute{
				Computed:            true,
				Description:         "Whether the zone is served by external nameservers.",
				MarkdownDescription: "Whether the zone is served by external nameservers.",
			},
			"zone_active": schema.BoolAttribute{
				Computed:            true,
				Description:         "Whether the zone is active.",
				MarkdownDescription: "Whether the zone is active.",
				PlanModifiers:       []planmodifier.Bool{boolplanmodifier.UseStateForUnknown()},
			},
			"zone_id": schema.StringAttribute{
				Computed:            true,
				Description:         "Zone id.",
				MarkdownDescription: "Zone id.",
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"zone_name": schema.StringAttribute{
				Required:            true,
				Description:         "Domain name.",
				MarkdownDescription: "Domain name.",
				PlanModifiers:       []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"zone_protected": schema.BoolAttribute{
				Computed:            true,
				Description:         "Whether the zone is protected against deletion.",
				MarkdownDescription: "Whether the zone is protected against deletion.",
				PlanModifiers:       []planmodifier.Bool{boolplanmodifier.UseStateForUnknown()},
			},

			"registered": schema.BoolAttribute{
				Computed: true, MarkdownDescription: "Whether the zone represents a registered domain.",
			},
			"domain_status": schema.StringAttribute{
				Computed: true, MarkdownDescription: "Domain registration status, if registered.",
			},
			"domain_expiry_date": schema.StringAttribute{
				Computed: true, MarkdownDescription: "Domain expiry date, if registered.",
			},
			"masters": masterServersSchema(),
			"nameservers": schema.SetAttribute{
				Optional: true, ElementType: types.StringType,
				MarkdownDescription: "Registry nameservers (at least 2) for an existing registered domain. Omitting leaves delegation unmanaged. Gigahost syncs apex NS records, but read-back can lag.",
				Validators:          []validator.Set{setvalidator.SizeAtLeast(2)},
			},
			"dnssec_enabled": schema.BoolAttribute{
				Optional: true, MarkdownDescription: "Enable or disable DNSSEC for a registered domain; nameserver changes are applied first.",
			},
			"dnssec_ds_records": schema.StringAttribute{
				Computed: true, MarkdownDescription: "DS record text returned by Gigahost when DNSSEC is being managed.",
			},
			"external_ds_records": externalDSRecordSchema(),
			"zone_type": schema.StringAttribute{
				Optional:            true,
				Computed:            true,
				Description:         "Zone type (NATIVE, MASTER, or SLAVE).",
				MarkdownDescription: "Zone type (NATIVE, MASTER, or SLAVE).",
				Default:             stringdefault.StaticString("NATIVE"),
				PlanModifiers:       []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
		},
	}
}

func (r *dnsZoneResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	c, ok := req.ProviderData.(*client.Client)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Resource Configure Type",
			fmt.Sprintf("Expected *client.Client, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)
		return
	}

	r.client = c
}

func (r *dnsZoneResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan dnsZoneResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Creating a DNS zone does not register a domain. Registry-level settings
	// are only safe to apply to imported, already registered zones.
	if !plan.Nameservers.IsNull() || !plan.DNSSECEnabled.IsNull() || !plan.ExternalDSRecords.IsNull() {
		resp.Diagnostics.AddError("Registered Domain Required",
			"Create the DNS zone first, or import the registered domain before configuring nameservers or DNSSEC.")
		return
	}
	var zone *client.DnsZone
	var err error
	if strings.EqualFold(plan.ZoneType.ValueString(), "SLAVE") {
		if plan.Masters.IsNull() {
			resp.Diagnostics.AddError("Masters Required",
				"SLAVE zones require masters with at least one primary server IP address.")
			return
		}
		masters, parseErr := listZoneStrings(ctx, plan.Masters)
		if parseErr != nil {
			resp.Diagnostics.AddError("Invalid Master Servers", parseErr.Error())
			return
		}
		zone, err = r.client.CreateSecondaryZone(ctx, plan.ZoneName.ValueString(), masters)
	} else {
		if !plan.Masters.IsNull() {
			resp.Diagnostics.AddError("Masters Only for SLAVE",
				"masters is only valid if zone_type = SLAVE.")
			return
		}
		zone, err = r.client.CreateZone(ctx, plan.ZoneName.ValueString(), plan.ZoneType.ValueString())
	}
	if err != nil {
		resp.Diagnostics.AddError("Unable to Create Gigahost DNS Zone", err.Error())
		return
	}

	state := dnsZoneToModel(zone)
	state.ZoneName = plan.ZoneName
	state.ZoneType = plan.ZoneType
	copyZoneSettings(&state, plan)

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *dnsZoneResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state dnsZoneResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	zone, err := r.client.GetZone(ctx, state.ZoneId.ValueString())
	if err != nil {
		if errors.Is(err, client.ErrNotFound) {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Unable to Read Gigahost DNS Zone", err.Error())
		return
	}

	previous := state
	state = dnsZoneToModel(zone)
	if !previous.ZoneName.IsNull() {
		state.ZoneName = previous.ZoneName
	}
	if !previous.ZoneType.IsNull() {
		state.ZoneType = previous.ZoneType
	}
	copyZoneSettings(&state, previous)
	if err := r.refreshZoneSettings(ctx, zone, &state); err != nil {
		resp.Diagnostics.AddError("Unable to Read Gigahost Zone Settings", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *dnsZoneResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var old, plan dnsZoneResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &old)...)
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if !plan.Masters.IsNull() && !strings.EqualFold(plan.ZoneType.ValueString(), "SLAVE") {
		resp.Diagnostics.AddError("Masters Only for SLAVE", "masters requires zone_type = SLAVE.")
		return
	}
	if err := r.applyZoneSettings(ctx, old.ZoneId.ValueString(), old, plan); err != nil {
		resp.Diagnostics.AddError("Unable to Update Gigahost Zone Settings", err.Error())
		return
	}
	// Populate computed properties, while retaining the planned registry values;
	// the registry can take time to reflect DNSSEC or delegation changes.
	zone, err := r.client.GetZone(ctx, old.ZoneId.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Unable to Read Updated Gigahost Zone", err.Error())
		return
	}
	state := dnsZoneToModel(zone)
	state.ZoneName = plan.ZoneName
	state.ZoneType = plan.ZoneType
	copyZoneSettings(&state, plan)
	if !plan.DNSSECEnabled.IsNull() && plan.DNSSECEnabled.ValueBool() {
		ds, err := r.client.GetDSRecords(ctx, zone.ZoneID)
		if err != nil {
			resp.Diagnostics.AddError("Unable to Read DNSSEC DS Records", err.Error())
			return
		}
		state.DNSSECDSRecords = types.StringValue(ds)
	} else {
		state.DNSSECDSRecords = types.StringNull()
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *dnsZoneResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state dnsZoneResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if err := r.client.DeleteZone(ctx, state.ZoneId.ValueString()); err != nil && !errors.Is(err, client.ErrNotFound) {
		resp.Diagnostics.AddError("Unable to Delete Gigahost DNS Zone", err.Error())
	}
}

func (r *dnsZoneResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("zone_id"), req, resp)
}

func dnsZoneToModel(z *client.DnsZone) dnsZoneResourceModel {
	state := dnsZoneResourceModel{
		ZoneId:            types.StringValue(z.ZoneID),
		ZoneName:          types.StringValue(z.ZoneName),
		ZoneType:          types.StringValue(z.ZoneType),
		ZoneActive:        types.BoolValue(bool(z.ZoneActive)),
		ZoneProtected:     types.BoolValue(bool(z.ZoneProtected)),
		ExternalDns:       types.BoolValue(bool(z.ExternalDNS)),
		Registered:        types.BoolNull(),
		Status:            types.StringNull(),
		ExpiryDate:        types.StringNull(),
		Masters:           types.SetNull(types.StringType),
		Nameservers:       types.SetNull(types.StringType),
		DNSSECEnabled:     types.BoolNull(),
		DNSSECDSRecords:   types.StringNull(),
		ExternalDSRecords: types.SetNull(externalDSRecordType()),
	}
	if z.Registered != nil {
		state.Registered = types.BoolValue(bool(*z.Registered))
	}
	if z.DomainStatus != "" {
		state.Status = types.StringValue(z.DomainStatus)
	}
	if z.DomainExpiry != "" {
		state.ExpiryDate = types.StringValue(z.DomainExpiry)
	}
	return state
}
