package dispenser

import "time"

type SpawnMode string

const (
	SpawnModeL1 SpawnMode = "l1"
	SpawnModeL2 SpawnMode = "l2"
)

type SpawnPlanetRequest struct {
	Star            string    `json:"star"`
	TargetOwner     string    `json:"targetOwner"`
	Mode            SpawnMode `json:"mode"`
	GenerateKeyfile bool      `json:"generateKeyfile"`
	MasterTicket    string    `json:"masterTicket,omitempty"`
	Passphrase      string    `json:"passphrase,omitempty"`
}

type SpawnPlanetResponse struct {
	Planet        string `json:"planet"`
	Mode          string `json:"mode"`
	TxID          string `json:"txId"`
	QueueRef      string `json:"queueRef,omitempty"`
	KeyfileBase64 string `json:"keyfileBase64,omitempty"`
}

type TransferResetRequest struct {
	NewMasterTicket string `json:"newMasterTicket"`
	Passphrase      string `json:"passphrase,omitempty"`
	ResetKeys       bool   `json:"resetKeys"`
}

type TransferResetResponse struct {
	Planet string `json:"planet"`
	TxID   string `json:"txId"`
}

type GeneratePassportRequest struct {
	MasterTicket string `json:"masterTicket"`
	Passphrase   string `json:"passphrase,omitempty"`
}

type GeneratePassportResponse struct {
	Planet        string    `json:"planet"`
	SizeBytes     int64     `json:"sizeBytes"`
	StoragePath   string    `json:"storagePath"`
	DownloadToken string    `json:"downloadToken"`
	ExpiresAt     time.Time `json:"expiresAt"`
}
