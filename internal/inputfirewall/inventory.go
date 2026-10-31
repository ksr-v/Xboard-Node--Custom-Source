package inputfirewall

type InventoryStatus struct {
	NFTToolPresent        bool     `json:"nft_tool_present"`
	IPTablesNFTPresent    bool     `json:"iptables_nft_present"`
	IPTablesLegacyPresent bool     `json:"iptables_legacy_present"`
	NativeNFT             string   `json:"native_nft"`
	Issues                []string `json:"issues"`
}

// Inventory only executes trusted, bounded read operations. Tool installation
// is reported independently of the active filter backends in Status.
func Inventory() InventoryStatus { return platformInventory() }
