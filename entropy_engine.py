import math
import collections

def calculate_entropy(file_path):
    """
    Calculates the Shannon Entropy of a file.
    Higher entropy (closer to 8.0) indicates encryption or compression.
    """
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
            if not data:
                return 0
            
            # Count the frequency of each byte (0-255)
            counter = collections.Counter(data)
            size = len(data)
            
            # Calculate Shannon Entropy
            entropy = 0
            for count in counter.values():
                probability = count / size
                entropy -= probability * math.log2(probability)
            
            return entropy
    except Exception as e:
        return 0

# Test the function if run directly
if __name__ == "__main__":
    # Test with a simple text file you might have
    path = "check.txt" 
    print(f"Entropy of {path}: {calculate_entropy(path):.2f}")
