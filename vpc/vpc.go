package vpc

import (
	_ "fmt"
)

type VpcZoneAssociation struct {
	VpcId     string `json:"vpcId,omitempty"`
	VpcCidr   string `json:"vpcCidr,omitempty"`
	VpcRegion string `json:"vpcRegion,omitempty"`
	AccountId string `json:"accountId,omitempty"`
}
