package usecases

import (
	"testing"
	"time"
)

func TestSegmentationCacheHitWithinTTL(t *testing.T) {
	uc := NewStrategyUsecase(nil)
	uc.putSegmentationCache("COGASA", map[string]any{"items": []any{"a"}})
	got, ok := uc.getSegmentationCache("COGASA")
	if !ok || got["items"] == nil {
		t.Fatalf("expected cache hit, ok=%v got=%#v", ok, got)
	}
	uc.segMu.Lock()
	entry := uc.segCache["COGASA"]
	entry.at = time.Now().Add(-segmentationCacheTTL - time.Second)
	uc.segCache["COGASA"] = entry
	uc.segMu.Unlock()
	if _, ok := uc.getSegmentationCache("COGASA"); ok {
		t.Fatal("expected TTL miss")
	}
}

func TestSegmentationCacheInvalidatedOnMutations(t *testing.T) {
	uc := NewStrategyUsecase(nil)
	uc.putSegmentationCache("COGASA", map[string]any{"items": []any{}})
	uc.invalidateSegmentationCache()
	if _, ok := uc.getSegmentationCache("COGASA"); ok {
		t.Fatal("expected invalidate")
	}
}
