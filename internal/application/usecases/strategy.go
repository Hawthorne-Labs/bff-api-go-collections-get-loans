package usecases

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/hawthorne/bff-api-go-collections-get-loans/internal/domain"
	"github.com/hawthorne/bff-api-go-collections-get-loans/internal/infrastructure/coreclient"
)

const segmentationCacheTTL = 30 * time.Second

type segmentationCacheEntry struct {
	at   time.Time
	data map[string]any
}

// StrategyUsecase handles all strategy/segmentation business logic.
type StrategyUsecase struct {
	core     *coreclient.CoreClient
	segMu    sync.Mutex
	segCache map[string]segmentationCacheEntry
}

// NewStrategyUsecase creates a new StrategyUsecase.
func NewStrategyUsecase(core *coreclient.CoreClient) *StrategyUsecase {
	return &StrategyUsecase{
		core:     core,
		segCache: make(map[string]segmentationCacheEntry),
	}
}

// GetSegmentation gets live account counts per priority bucket by marca.
func (u *StrategyUsecase) GetSegmentation(ctx context.Context, traceID, tenantID, userEmail, marca string) (map[string]any, error) {
	key := strings.TrimSpace(marca)
	if cached, ok := u.getSegmentationCache(key); ok {
		return cached, nil
	}
	result, err := u.core.GetStrategySegmentation(ctx, traceID, tenantID, userEmail, marca)
	if err != nil {
		return nil, err
	}
	u.putSegmentationCache(key, result)
	return result, nil
}

// ListAssignments gets strategy assignment audit trail.
func (u *StrategyUsecase) ListAssignments(ctx context.Context, traceID, tenantID, userEmail string, limit, offset int, marca string) (map[string]any, error) {
	params := map[string]string{
		"limit":  fmt.Sprintf("%d", limit),
		"offset": fmt.Sprintf("%d", offset),
	}
	if marca != "" {
		params["marca"] = marca
	}
	return u.core.ListStrategyAssignments(ctx, traceID, tenantID, userEmail, params)
}

// CreateAssignment persists a strategy assignment.
func (u *StrategyUsecase) CreateAssignment(ctx context.Context, traceID, tenantID, userEmail string, body map[string]any) (map[string]any, error) {
	if err := validateAssignmentBody(body); err != nil {
		return nil, err
	}
	result, err := u.core.CreateStrategyAssignment(ctx, traceID, tenantID, userEmail, body)
	if err != nil {
		return nil, err
	}
	u.invalidateSegmentationCache()
	return result, nil
}

// CleanQueue persists a queue-clean action.
func (u *StrategyUsecase) CleanQueue(ctx context.Context, traceID, tenantID, userEmail string, body map[string]any) (map[string]any, error) {
	marca, _ := body["marca"].(string)
	if strings.TrimSpace(marca) == "" {
		return nil, domain.NewHTTPBusinessError(422, domain.ValidationFailed, "marca es requerida")
	}
	result, err := u.core.CleanStrategyQueue(ctx, traceID, tenantID, userEmail, body)
	if err != nil {
		return nil, err
	}
	u.invalidateSegmentationCache()
	return result, nil
}

// WarmReadPaths pre-heats Core strategy queries (Python warm_strategy_read_paths parity).
func (u *StrategyUsecase) WarmReadPaths(ctx context.Context, userEmail string, marcas []string) {
	email := strings.TrimSpace(userEmail)
	if email == "" {
		return
	}
	for _, marca := range marcas {
		normalized := strings.TrimSpace(marca)
		if normalized == "" {
			continue
		}
		_, _ = u.core.GetStrategySegmentation(ctx, "startup-warmup", "default", email, normalized)
	}
	_, _ = u.core.ListStrategyAssignments(ctx, "startup-warmup", "default", email, map[string]string{
		"limit":  "1",
		"offset": "0",
	})
}

func (u *StrategyUsecase) getSegmentationCache(key string) (map[string]any, bool) {
	u.segMu.Lock()
	defer u.segMu.Unlock()
	entry, ok := u.segCache[key]
	if !ok || time.Since(entry.at) > segmentationCacheTTL {
		return nil, false
	}
	return cloneMap(entry.data), true
}

func (u *StrategyUsecase) putSegmentationCache(key string, data map[string]any) {
	u.segMu.Lock()
	defer u.segMu.Unlock()
	u.segCache[key] = segmentationCacheEntry{at: time.Now(), data: cloneMap(data)}
}

func (u *StrategyUsecase) invalidateSegmentationCache() {
	u.segMu.Lock()
	defer u.segMu.Unlock()
	u.segCache = make(map[string]segmentationCacheEntry)
}

func cloneMap(in map[string]any) map[string]any {
	if in == nil {
		return nil
	}
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func validateAssignmentBody(body map[string]any) error {
	marca, _ := body["marca"].(string)
	if strings.TrimSpace(marca) == "" {
		return domain.NewHTTPBusinessError(422, domain.ValidationFailed, "marca es requerida")
	}
	prioridad, ok := asNonNegInt(body["prioridad"])
	if !ok || prioridad > 4 {
		return domain.NewHTTPBusinessError(422, domain.ValidationFailed, "prioridad debe estar entre 0 y 4")
	}
	if prioridad == 4 {
		if body["diasMoraMaximo"] == nil {
			body["diasMoraMaximo"] = domain.MaxPriority4DaysPastDue
		} else {
			days, ok := asNonNegInt(body["diasMoraMaximo"])
			if !ok || days <= 90 {
				return domain.NewHTTPBusinessError(422, domain.ValidationFailed, "diasMoraMaximo invalido para prioridad 4")
			}
		}
	}
	return validateAssignmentDistribution(body)
}

func validateAssignmentDistribution(body map[string]any) error {
	cuentas, ok := asNonNegInt(body["cuentas"])
	if !ok || cuentas <= 0 {
		return domain.NewHTTPBusinessError(422, domain.ValidationFailed, "cuentas debe ser mayor a cero")
	}

	rawDist, ok := body["distribucion"].([]any)
	if !ok || len(rawDist) == 0 {
		return domain.NewHTTPBusinessError(422, domain.ValidationFailed, "distribucion es requerida")
	}

	sum := 0
	for _, row := range rawDist {
		item, ok := row.(map[string]any)
		if !ok {
			return domain.NewHTTPBusinessError(422, domain.ValidationFailed, "Validacion fallida.")
		}
		rowCuentas, ok := asNonNegInt(item["cuentas"])
		if !ok || rowCuentas <= 0 {
			return domain.NewHTTPBusinessError(422, domain.ValidationFailed, "Cada agente en distribucion debe recibir al menos una cuenta")
		}
		sum += rowCuentas
	}

	if sum != cuentas {
		return domain.NewHTTPBusinessError(422, domain.ValidationFailed, "La suma de distribucion debe coincidir con cuentas")
	}
	return nil
}

func asNonNegInt(v any) (int, bool) {
	switch n := v.(type) {
	case int:
		return n, n >= 0
	case int32:
		return int(n), n >= 0
	case int64:
		return int(n), n >= 0
	case float64:
		if n < 0 || n != float64(int(n)) {
			return 0, false
		}
		return int(n), true
	default:
		return 0, false
	}
}
