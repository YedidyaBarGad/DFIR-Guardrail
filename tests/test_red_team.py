import pytest
from src.red_team import RedTeamPoisoner

def test_generate_benign_dataset():
    poisoner = RedTeamPoisoner()
    dataset = poisoner.generate_dataset(num_samples=10, poison_ratio=0.0)
    
    assert len(dataset) == 10
    for item in dataset:
        assert not item["is_malicious"]
        assert "artifact" in item
        assert "id" in item

def test_generate_poisoned_dataset():
    poisoner = RedTeamPoisoner()
    dataset = poisoner.generate_dataset(num_samples=100, poison_ratio=0.2)
    
    malicious_count = sum(1 for item in dataset if item["is_malicious"])
    # Probabilistic generation, should be roughly 20
    assert 10 <= malicious_count <= 30
