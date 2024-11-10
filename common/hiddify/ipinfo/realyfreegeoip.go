package ipinfo

import (
	"context"

	N "github.com/sagernet/sing/common/network"
)

// ReallyFreeGeoIPProvider struct and implementation.
type ReallyFreeGeoIPProvider struct {
	BaseProvider
}

// NewReallyFreeGeoIPProvider initializes a new ReallyFreeGeoIPProvider.
func NewReallyFreeGeoIPProvider() *ReallyFreeGeoIPProvider {
	return &ReallyFreeGeoIPProvider{
		BaseProvider: BaseProvider{URL: "https://reallyfreegeoip.org/json/"},
	}
}

// GetIPInfo fetches and parses IP information from reallyfreegeoip.org.
func (p *ReallyFreeGeoIPProvider) GetIPInfo(ctx context.Context, dialer N.Dialer) (*IpInfo, uint16, error) {
	info := &IpInfo{}
	data, t, err := p.fetchData(ctx, dialer)
	if err != nil {
		return nil, t, err
	}

	if ip, ok := data["ip"].(string); ok {
		info.IP = ip
	}
	if countryCode, ok := data["country_code"].(string); ok {
		info.CountryCode = countryCode
	}
	if countryName, ok := data["country_name"].(string); ok {
		info.Country = countryName
	}
	if regionCode, ok := data["region_code"].(string); ok {
		info.Region = regionCode
	}
	if regionName, ok := data["region_name"].(string); ok {
		info.RegionName = regionName
	}
	if city, ok := data["city"].(string); ok {
		info.City = city
	}
	if zipCode, ok := data["zip_code"].(string); ok {
		info.PostalCode = zipCode
	}
	if timeZone, ok := data["time_zone"].(string); ok {
		info.Timezone = timeZone
	}
	if latitude, ok := data["latitude"].(float64); ok {
		info.Latitude = latitude
	}
	if longitude, ok := data["longitude"].(float64); ok {
		info.Longitude = longitude
	}

	return info, t, nil
}
