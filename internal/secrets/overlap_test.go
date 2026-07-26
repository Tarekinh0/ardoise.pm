package secrets

import "testing"

func TestResolveOverlapsEmpty(t *testing.T) {
	result := resolveOverlaps(nil)
	if result != nil {
		t.Error("resolveOverlaps of nil should return nil")
	}
	result = resolveOverlaps([]Entity{})
	if len(result) != 0 {
		t.Error("resolveOverlaps of empty slice should return empty")
	}
}

func TestResolveOverlapsSingleEntity(t *testing.T) {
	entities := []Entity{
		{Type: Secret, Value: "sk-abcdef", Confidence: 0.85, Source: SourcePrefix, Start: 0, End: 9},
	}
	result := resolveOverlaps(entities)
	if len(result) != 1 {
		t.Fatalf("expected 1 entity, got %d", len(result))
	}
	if result[0].Start != 0 || result[0].End != 9 {
		t.Error("entity positions changed")
	}
}

func TestResolveOverlapsNoOverlap(t *testing.T) {
	entities := []Entity{
		{Type: Secret, Value: "sk-abc", Confidence: 0.85, Source: SourcePrefix, Start: 0, End: 6},
		{Type: JWT, Value: "a.b.c", Confidence: 0.75, Source: SourceStructural, Start: 10, End: 15},
	}
	result := resolveOverlaps(entities)
	if len(result) != 2 {
		t.Fatalf("expected 2 non-overlapping entities, got %d", len(result))
	}
}

func TestResolveOverlapsAdjacent(t *testing.T) {
	// Adjacent entities (End_A == Start_B) are NOT overlapping.
	entities := []Entity{
		{Type: Secret, Value: "sk-abcd", Confidence: 0.85, Source: SourcePrefix, Start: 0, End: 7},
		{Type: JWT, Value: "a.b.c", Confidence: 0.80, Source: SourceStructural, Start: 7, End: 12},
	}
	result := resolveOverlaps(entities)
	if len(result) != 2 {
		t.Fatalf("adjacent entities should both survive, got %d", len(result))
	}
}

func TestResolveOverlapsHigherConfidenceWins(t *testing.T) {
	entities := []Entity{
		{Type: PrivateKey, Value: "-----BEGIN", Confidence: 0.85, Source: SourcePEMArmor, Start: 0, End: 10},
		{Type: Secret, Value: "-----BEGIN-", Confidence: 0.95, Source: SourceEntropy, Start: 0, End: 11},
	}
	result := resolveOverlaps(entities)
	if len(result) != 1 {
		t.Fatalf("expected 1 winner, got %d", len(result))
	}
	if result[0].Confidence != 0.95 {
		t.Error("higher confidence entity should win")
	}
}

func TestResolveOverlapsTypePriority(t *testing.T) {
	// Same confidence, different types: JWT outranks SECRET.
	entities := []Entity{
		{Type: Secret, Value: "sk-test123", Confidence: 0.85, Source: SourcePrefix, Start: 0, End: 10},
		{Type: JWT, Value: "a.b.c", Confidence: 0.85, Source: SourceStructural, Start: 0, End: 7},
	}
	result := resolveOverlaps(entities)
	if len(result) != 1 {
		t.Fatalf("expected 1 winner, got %d", len(result))
	}
	if result[0].Type != JWT {
		t.Errorf("JWT should have priority over SECRET, got %s", result[0].Type)
	}
}

func TestResolveOverlapsLongerSpanWins(t *testing.T) {
	// Same type, same confidence, different lengths.
	entities := []Entity{
		{Type: Secret, Value: "ab", Confidence: 0.85, Source: SourceEntropy, Start: 0, End: 2},
		{Type: Secret, Value: "abcd", Confidence: 0.85, Source: SourceEntropy, Start: 0, End: 4},
	}
	result := resolveOverlaps(entities)
	if len(result) != 1 {
		t.Fatalf("expected 1 winner, got %d", len(result))
	}
	if result[0].End-result[0].Start != 4 {
		t.Error("longer span should win")
	}
}

func TestResolveOverlapsMultipleOverlaps(t *testing.T) {
	// Complex scenario with multiple overlapping entities.
	entities := []Entity{
		{Type: Secret, Value: "sk-abcdefgh", Confidence: 0.90, Source: SourcePrefix, Start: 0, End: 11},
		{Type: Secret, Value: "efgh1234", Confidence: 0.70, Source: SourceEntropy, Start: 5, End: 13},
		{Type: JWT, Value: "a.b.c", Confidence: 0.80, Source: SourceStructural, Start: 15, End: 20},
		{Type: Secret, Value: "secret123", Confidence: 0.70, Source: SourceEntropy, Start: 15, End: 24},
	}
	result := resolveOverlaps(entities)
	// First overlap (0-11 vs 5-13): 0.90 > 0.70, the prefix match wins.
	// Second overlap (15-20 vs 15-24): JWT 0.80 > SECRET 0.70, JWT wins.
	if len(result) != 2 {
		t.Fatalf("expected 2 entities, got %d", len(result))
	}
	var prefixFound, jwtFound bool
	for _, e := range result {
		if e.Source == SourcePrefix && e.End == 11 {
			prefixFound = true
		}
		if e.Type == JWT && e.End == 20 {
			jwtFound = true
		}
	}
	if !prefixFound || !jwtFound {
		t.Errorf("winners = %v", result)
	}
}

func TestEntityTypePriorityOrderUnknownType(t *testing.T) {
	if entityTypePriorityOrder(EntityType("INCONNU")) != 999 {
		t.Error("unknown types must rank last")
	}
}
