import math

def calculate_entropy(s: str) -> float:
    """
    Calculates the Shannon Entropy of a string to detect high-randomness secrets (e.g., API keys, hashes).
    Formula: H(X) = - sum(P(x) * log2(P(x)))
    """
    if not s:
        return 0.0
    
    char_counts = {}
    for char in s:
        char_counts[char] = char_counts.get(char, 0) + 1
        
    entropy = 0.0
    total_len = len(s)
    for count in char_counts.values():
        p = count / total_len
        entropy -= p * math.log2(p)
        
    return entropy
