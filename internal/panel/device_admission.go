package panel

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"
)

// AcquireDevice reserves one globally counted source IP. Identity and machine
// credentials remain in the JSON body, and response bodies are never logged.
func (c *Client) AcquireDevice(ctx context.Context, userUUID, ip, token string, interval int) error {
	payload := map[string]interface{}{"user_uuid": userUUID, "ip": ip, "lease_token": token, "report_interval": interval}
	var response struct {
		Data struct {
			Allowed    bool   `json:"allowed"`
			LeaseToken string `json:"lease_token"`
			TTL        int    `json:"ttl"`
		} `json:"data"`
	}
	if err := c.deviceAdmissionRequest(ctx, "/api/v2/server/device/acquire", payload, &response); err != nil {
		return err
	}
	if !response.Data.Allowed {
		return errors.New("device admission denied")
	}
	// Protocol v1's forwarding watchdog requires a minimum 60-second lease.
	if response.Data.LeaseToken != token || response.Data.TTL < 60 {
		return errors.New("invalid device admission response")
	}
	return nil
}

// ReleaseDevice uses a generation token so a late release cannot remove a new
// connection's reservation for the same node, user and source IP.
func (c *Client) ReleaseDevice(ctx context.Context, userUUID, ip, token string) error {
	payload := map[string]interface{}{"user_uuid": userUUID, "ip": ip, "lease_token": token}
	return c.deviceAdmissionRequest(ctx, "/api/v2/server/device/release", payload, nil)
}

func (c *Client) SupportsRetainedDeviceRelease() bool {
	return c.retainedDeviceRelease.Load()
}

func (c *Client) ReleaseDeviceRetainingIP(ctx context.Context, userUUID, ip, token string) error {
	if !c.SupportsRetainedDeviceRelease() {
		return errors.New("retained device release unavailable")
	}
	payload := map[string]interface{}{"user_uuid": userUUID, "ip": ip, "lease_token": token, "retain_ip": true}
	return c.deviceAdmissionRequest(ctx, "/api/v2/server/device/release", payload, nil)
}

func (c *Client) deviceAdmissionRequest(parent context.Context, path string, payload map[string]interface{}, result interface{}) error {
	ctx, cancel := context.WithTimeout(parent, 2*time.Second)
	defer cancel()
	c.injectAuth(payload)
	body, err := json.Marshal(payload)
	if err != nil {
		return errors.New("invalid device admission request")
	}
	response, err := c.doRequestContext(ctx, http.MethodPost, path, body, "")
	if err != nil {
		return errors.New("device admission unavailable")
	}
	defer drainAndClose(response.Body)
	if response.StatusCode != http.StatusOK {
		return errors.New("device admission unavailable")
	}
	if result != nil {
		if err := json.NewDecoder(response.Body).Decode(result); err != nil {
			return errors.New("invalid device admission response")
		}
	}
	return nil
}
