import math
from collections import Counter

def calculate_entropy(text):
    """
    Calculates the Shannon entropy of a string.
    High entropy suggests randomness, a potential indicator of malware.
    """
    if not text:
        return 0
    # Get the frequency of each character
    entropy = 0
    text_len = len(text)
    for count in Counter(text).values():
        # calculate probability
        p_x = count / text_len
        # calculate entropy
        entropy += - p_x * math.log2(p_x)
    return entropy