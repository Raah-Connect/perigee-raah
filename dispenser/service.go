package dispenser

import (
	"context"
	"fmt"
	"strings"
	"time"
)

type PlanetService interface {
	SpawnPlanet(ctx context.Context, req SpawnPlanetRequest) (SpawnPlanetResponse, error)
	TransferAndReset(ctx context.Context, planet string, req TransferResetRequest) (TransferResetResponse, error)
	GeneratePassportZip(ctx context.Context, planet string, req GeneratePassportRequest) (GeneratePassportResponse, error)
}

type NoopPlanetService struct{}

func NewNoopPlanetService() *NoopPlanetService {
	return &NoopPlanetService{}
}

func (s *NoopPlanetService) SpawnPlanet(_ context.Context, req SpawnPlanetRequest) (SpawnPlanetResponse, error) {
	mode := strings.ToLower(string(req.Mode))
	if mode == "" {
		mode = string(SpawnModeL1)
	}
	if mode != string(SpawnModeL1) && mode != string(SpawnModeL2) {
		return SpawnPlanetResponse{}, fmt.Errorf("unsupported mode: %s", req.Mode)
	}
	if req.Star == "" {
		return SpawnPlanetResponse{}, fmt.Errorf("star is required")
	}
	if req.TargetOwner == "" {
		return SpawnPlanetResponse{}, fmt.Errorf("targetOwner is required")
	}

	resp := SpawnPlanetResponse{
		Planet:   "~samplel-palnet",
		Mode:     mode,
		TxID:     "0xspawn-placeholder-tx",
		QueueRef: "queue-placeholder",
	}
	if req.GenerateKeyfile {
		resp.KeyfileBase64 = "BASE64_KEYFILE_PLACEHOLDER"
	}
	return resp, nil
}

func (s *NoopPlanetService) TransferAndReset(_ context.Context, planet string, req TransferResetRequest) (TransferResetResponse, error) {
	if planet == "" {
		return TransferResetResponse{}, fmt.Errorf("planet is required")
	}
	if req.NewMasterTicket == "" {
		return TransferResetResponse{}, fmt.Errorf("newMasterTicket is required")
	}
	return TransferResetResponse{
		Planet: planet,
		TxID:   "0xtransfer-reset-placeholder-tx",
	}, nil
}

func (s *NoopPlanetService) GeneratePassportZip(_ context.Context, planet string, req GeneratePassportRequest) (GeneratePassportResponse, error) {
	if planet == "" {
		return GeneratePassportResponse{}, fmt.Errorf("planet is required")
	}
	if req.MasterTicket == "" {
		return GeneratePassportResponse{}, fmt.Errorf("masterTicket is required")
	}
	return GeneratePassportResponse{
		Planet:        planet,
		SizeBytes:     784 * 1024,
		StoragePath:   "/var/lib/perigee/passports/placeholder.zip",
		DownloadToken: "download-token-placeholder",
		ExpiresAt:     time.Now().UTC().Add(24 * time.Hour),
	}, nil
}
