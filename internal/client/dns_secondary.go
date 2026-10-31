package client

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// ErrSecondaryUnavailable is returned when Gigahost has secondary DNS disabled.
var ErrSecondaryUnavailable = errors.New("gigahost secondary DNS is not available at the moment (the Gigahost API refused the request with HTTP 403); retry later or contact Gigahost support")

func wrapSecondaryError(err error) error {
	var apiErr *Error
	if errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusForbidden &&
		strings.Contains(strings.ToLower(apiErr.Message), "secondary dns is not available") {
		return fmt.Errorf("%w: %s", ErrSecondaryUnavailable, apiErr.Message)
	}
	return err
}

type updateSecondaryMastersRequest struct {
	Masters []string `json:"masters"`
}

// UpdateSecondaryMasters changes the masters of a SLAVE zone in place and
// requests a new transfer (PUT /dns/zones/{id}/secondary, as used by the panel).
func (c *Client) UpdateSecondaryMasters(ctx context.Context, zoneID string, masters []string) error {
	if len(masters) == 0 {
		return fmt.Errorf("gigahost: at least one master is required")
	}
	req, err := c.newRequest(ctx, http.MethodPut, "dns/zones/"+url.PathEscape(zoneID)+"/secondary", nil, updateSecondaryMastersRequest{Masters: masters})
	if err != nil {
		return err
	}
	return wrapSecondaryError(c.sendRequest(req, nil))
}

type createSecondaryZoneRequest struct {
	ZoneName string   `json:"zone_name"`
	Masters  []string `json:"masters"`
}

// CreateSecondaryZone creates a secondary (slave) zone that is transferred
// from the given master servers. It uses POST /dns/zones/secondary, which is
// not part of the public API documentation but is used by the Gigahost panel.
func (c *Client) CreateSecondaryZone(ctx context.Context, zoneName string, masters []string) (*DnsZone, error) {
	if len(masters) == 0 {
		return nil, fmt.Errorf("gigahost: at least one master is required")
	}
	req, err := c.newRequest(ctx, http.MethodPost, "dns/zones/secondary", nil, createSecondaryZoneRequest{ZoneName: zoneName, Masters: masters})
	if err != nil {
		return nil, err
	}
	if err := c.sendRequest(req, nil); err != nil {
		return nil, wrapSecondaryError(err)
	}

	zones, err := c.ListDnsZones(ctx)
	if err != nil {
		return nil, err
	}
	for i := range zones {
		if strings.EqualFold(zones[i].ZoneName, zoneName) {
			return &zones[i], nil
		}
	}
	return nil, fmt.Errorf("zone %q was created but could not be found on the account", zoneName)
}

// SplitMasters splits the zone_masters field of a zone into individual hosts.
func SplitMasters(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == ';' || r == ' ' || r == '\n' || r == '\t'
	})
}
