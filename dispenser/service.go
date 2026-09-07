package dispenser

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Native-Planet/perigee/abi/ecliptic"
	"github.com/Native-Planet/perigee/libprg"
	"github.com/Native-Planet/perigee/pontifex"
	"github.com/Native-Planet/perigee/roller"
	perigeeTypes "github.com/Native-Planet/perigee/types"

	"github.com/deelawn/urbit-gob/co"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
)

const passportStorageDir = "/var/lib/perigee/passports"

const passportTTL = 24 * time.Hour

type NoopPlanetService struct{}

type LivePlanetService struct {
	rpc *perigeeTypes.Client
}

type PlanetService interface {
	SpawnPlanet(ctx context.Context, req SpawnPlanetRequest) (SpawnPlanetResponse, error)
	TransferAndReset(ctx context.Context, planet string, req TransferResetRequest) (TransferResetResponse, error)
	GeneratePassportZip(ctx context.Context, planet string, req GeneratePassportRequest) (GeneratePassportResponse, error)
	ResolvePassportPath(ctx context.Context, planet, token string) (string, error)
}

func (s *LivePlanetService) ResolvePassportPath(_ context.Context, planet, token string) (string, error) {
	if planet == "" || token == "" {
		return "", fmt.Errorf("planet and token are required")
	}
	if strings.ContainsAny(token, "/\\.") {
		return "", fmt.Errorf("invalid token")
	}
	trimmed := strings.TrimPrefix(planet, "~")
	path := filepath.Join(passportStorageDir, fmt.Sprintf("%s-%s.zip", trimmed, token))

	info, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("passport not found")
	}
	if time.Since(info.ModTime()) > passportTTL {
		_ = os.Remove(path)
		return "", fmt.Errorf("passport expired")
	}
	return path, nil
}

func NewNoopPlanetService() *NoopPlanetService {
	return &NoopPlanetService{}
}

func NewLivePlanetService() *LivePlanetService {
	return &LivePlanetService{
		rpc: &perigeeTypes.Client{
			Endpoint:   roller.RollerURL,
			HttpClient: nil,
		},
	}
}

func NewPlanetServiceFromEnv() PlanetService {
	return NewLivePlanetService()
}

func (s *LivePlanetService) SpawnPlanet(ctx context.Context, req SpawnPlanetRequest) (SpawnPlanetResponse, error) {
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
	if _, err := perigeeTypes.ValidateAddress(req.TargetOwner, false); err != nil {
		return SpawnPlanetResponse{}, fmt.Errorf("invalid targetOwner: %w", err)
	}
	if req.MasterTicket == "" {
		return SpawnPlanetResponse{}, fmt.Errorf("masterTicket is required")
	}
	if req.GenerateKeyfile {
		return SpawnPlanetResponse{}, fmt.Errorf("generateKeyfile is not supported during spawn; generate it after confirming the spawned point")
	}

	privKey, signerAddr, pointInfo, _, _, err := libprg.ValidateKey(ctx, req.Star, req.MasterTicket, req.Passphrase, "", false)
	if err != nil {
		return SpawnPlanetResponse{}, fmt.Errorf("validate signing key: %w", err)
	}

	starPatp, _, err := perigeeTypes.ValidateAndNormalizePatp(req.Star)
	if err != nil {
		return SpawnPlanetResponse{}, fmt.Errorf("invalid star: %w", err)
	}

	spawnNum, spawnPatp, err := s.pickUnspawnedPoint(ctx, starPatp)
	if err != nil {
		return SpawnPlanetResponse{}, err
	}

	if mode == string(SpawnModeL1) {
		if pointInfo.Dominion != "l1" {
			return SpawnPlanetResponse{}, fmt.Errorf("%s is %s; requested mode is l1", starPatp, pointInfo.Dominion)
		}
		txHash, err := l1Spawn(ctx, privKey, uint32(spawnNum), req.TargetOwner)
		if err != nil {
			return SpawnPlanetResponse{}, err
		}
		return SpawnPlanetResponse{
			Planet: spawnPatp,
			Mode:   mode,
			TxID:   txHash,
		}, nil
	}

	if pointInfo.Dominion != "l2" {
		return SpawnPlanetResponse{}, fmt.Errorf("%s is %s; requested mode is l2", starPatp, pointInfo.Dominion)
	}
	tx, err := roller.Client.Spawn(ctx, starPatp, uint32(spawnNum), req.TargetOwner, signerAddr, privKey)
	if err != nil {
		return SpawnPlanetResponse{}, fmt.Errorf("l2 spawn failed: %w", err)
	}
	return SpawnPlanetResponse{
		Planet:   spawnPatp,
		Mode:     mode,
		TxID:     tx.Hash,
		QueueRef: tx.Signature,
	}, nil
}

func (s *NoopPlanetService) ResolvePassportPath(_ context.Context, planet, token string) (string, error) {
	if planet == "" || token == "" {
		return "", fmt.Errorf("planet and token are required")
	}
	return "/var/lib/perigee/passports/placeholder.zip", nil
}

func (s *LivePlanetService) TransferAndReset(_ context.Context, planet string, req TransferResetRequest) (TransferResetResponse, error) {
	if planet == "" {
		return TransferResetResponse{}, fmt.Errorf("planet is required")
	}
	if req.NewMasterTicket == "" {
		return TransferResetResponse{}, fmt.Errorf("newMasterTicket is required")
	}
	return TransferResetResponse{}, fmt.Errorf("not implemented")
}

func (s *LivePlanetService) GeneratePassportZip(ctx context.Context, planet string, req GeneratePassportRequest) (GeneratePassportResponse, error) {
	if planet == "" {
		return GeneratePassportResponse{}, fmt.Errorf("planet is required")
	}
	if req.MasterTicket == "" {
		return GeneratePassportResponse{}, fmt.Errorf("masterTicket is required")
	}

	point, err := libprg.Point(ctx, planet)
	if err != nil {
		return GeneratePassportResponse{}, fmt.Errorf("fetch point info: %w", err)
	}
	life, err := strconv.Atoi(point.Point.Network.Keys.Life)
	if err != nil {
		return GeneratePassportResponse{}, fmt.Errorf("invalid life value: %w", err)
	}

	wallet, err := libprg.Wallet(ctx, planet, req.MasterTicket, req.Passphrase, life)
	if err != nil {
		return GeneratePassportResponse{}, fmt.Errorf("generate wallet: %w", err)
	}
	keyfile, err := libprg.Keyfile(ctx, planet, req.MasterTicket, req.Passphrase, life)
	if err != nil {
		return GeneratePassportResponse{}, fmt.Errorf("generate keyfile: %w", err)
	}
	sigilSVG, err := pontifex.GenerateSigil(perigeeTypes.PxSvgConfig{Point: planet, Size: 256})
	if err != nil {
		return GeneratePassportResponse{}, fmt.Errorf("generate sigil: %w", err)
	}

	walletJSON, err := json.Marshal(wallet)
	if err != nil {
		return GeneratePassportResponse{}, fmt.Errorf("marshal wallet: %w", err)
	}
	var walletMap map[string]interface{}
	if err := json.Unmarshal(walletJSON, &walletMap); err != nil {
		return GeneratePassportResponse{}, fmt.Errorf("decode wallet: %w", err)
	}

	trimmed := strings.TrimPrefix(planet, "~")
	walletNFO := pontifex.FormatToNFO(walletMap, fmt.Sprintf("%s PASSPORT", strings.ToUpper(planet)))

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	files := map[string]string{
		trimmed + "-wallet.nfo":                 walletNFO,
		fmt.Sprintf("%s-%d.key", trimmed, life): keyfile,
		trimmed + "-sigil.svg":                  sigilSVG,
	}
	for name, content := range files {
		fw, err := zw.Create(name)
		if err != nil {
			return GeneratePassportResponse{}, fmt.Errorf("zip create %s: %w", name, err)
		}
		if _, err := fw.Write([]byte(content)); err != nil {
			return GeneratePassportResponse{}, fmt.Errorf("zip write %s: %w", name, err)
		}
	}
	if err := zw.Close(); err != nil {
		return GeneratePassportResponse{}, fmt.Errorf("close zip: %w", err)
	}

	if err := os.MkdirAll(passportStorageDir, 0700); err != nil {
		return GeneratePassportResponse{}, fmt.Errorf("create storage dir: %w", err)
	}
	tokenBytes := make([]byte, 16)
	if _, err := rand.Read(tokenBytes); err != nil {
		return GeneratePassportResponse{}, fmt.Errorf("generate token: %w", err)
	}
	token := hex.EncodeToString(tokenBytes)
	storagePath := filepath.Join(passportStorageDir, fmt.Sprintf("%s-%s.zip", trimmed, token))
	if err := os.WriteFile(storagePath, buf.Bytes(), 0600); err != nil {
		return GeneratePassportResponse{}, fmt.Errorf("write zip: %w", err)
	}

	return GeneratePassportResponse{
		Planet:        planet,
		SizeBytes:     int64(buf.Len()),
		StoragePath:   storagePath,
		DownloadToken: token,
		ExpiresAt:     time.Now().UTC().Add(24 * time.Hour),
	}, nil
}

func (s *LivePlanetService) pickUnspawnedPoint(ctx context.Context, starPatp string) (uint64, string, error) {
	params := struct {
		Ship string `json:"ship"`
	}{
		Ship: starPatp,
	}
	result, err := s.rpc.DoRequest(ctx, "getUnspawned", params)
	if err != nil {
		return 0, "", fmt.Errorf("get unspawned points: %w", err)
	}

	var nums []uint64
	if err := json.Unmarshal(result, &nums); err == nil && len(nums) > 0 {
		if nums[0] > uint64(^uint32(0)) {
			return 0, "", fmt.Errorf("point %d is out of uint32 range", nums[0])
		}
		patp, err := co.Point2Patp(new(big.Int).SetUint64(nums[0]))
		if err != nil {
			return 0, "", fmt.Errorf("convert point %d to patp: %w", nums[0], err)
		}
		return nums[0], patp, nil
	}

	var ships []perigeeTypes.ShipInfo
	if err := json.Unmarshal(result, &ships); err == nil && len(ships) > 0 {
		first := ships[0].Name
		if first == "" {
			first = ships[0].Address
		}
		patp, pointNum, err := perigeeTypes.ValidateAndNormalizePatp(first)
		if err != nil {
			return 0, "", fmt.Errorf("invalid unspawned point from response: %w", err)
		}
		return uint64(pointNum), patp, nil
	}

	var pointStrs []string
	if err := json.Unmarshal(result, &pointStrs); err == nil && len(pointStrs) > 0 {
		if n, err := strconv.ParseUint(pointStrs[0], 10, 64); err == nil {
			if n > uint64(^uint32(0)) {
				return 0, "", fmt.Errorf("point %d is out of uint32 range", n)
			}
			patp, err := co.Point2Patp(new(big.Int).SetUint64(n))
			if err != nil {
				return 0, "", fmt.Errorf("convert point %d to patp: %w", n, err)
			}
			return n, patp, nil
		}
		patp, pointNum, err := perigeeTypes.ValidateAndNormalizePatp(pointStrs[0])
		if err != nil {
			return 0, "", fmt.Errorf("invalid unspawned point from response: %w", err)
		}
		return uint64(pointNum), patp, nil
	}

	return 0, "", fmt.Errorf("no unspawned points available for %s", starPatp)
}

func l1Spawn(ctx context.Context, privateKey *ecdsa.PrivateKey, point uint32, targetOwner string) (string, error) {
	ethProvider := os.Getenv("ETH_PROVIDER")
	if ethProvider == "" {
		return "", fmt.Errorf("ETH_PROVIDER is required for l1 spawn")
	}
	client, err := ethclient.DialContext(ctx, ethProvider)
	if err != nil {
		return "", fmt.Errorf("connect Ethereum provider: %w", err)
	}
	defer client.Close()

	chainID, err := client.NetworkID(ctx)
	if err != nil {
		return "", fmt.Errorf("get chain ID: %w", err)
	}
	auth, err := bind.NewKeyedTransactorWithChainID(privateKey, chainID)
	if err != nil {
		return "", fmt.Errorf("create signer: %w", err)
	}
	auth.Context = ctx

	gasPrice, err := client.SuggestGasPrice(ctx)
	if err == nil {
		auth.GasPrice = gasPrice
	}

	eclip, err := ecliptic.NewEcliptic(common.HexToAddress(libprg.EclipticContract), client)
	if err != nil {
		return "", fmt.Errorf("bind ecliptic contract: %w", err)
	}
	tx, err := eclip.Spawn(auth, point, common.HexToAddress(targetOwner))
	if err != nil {
		return "", fmt.Errorf("submit spawn tx: %w", err)
	}
	return tx.Hash().Hex(), nil
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
