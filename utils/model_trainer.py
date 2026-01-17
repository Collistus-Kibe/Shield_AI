# File: utils/model_trainer.py
import os
import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier

# Define where the brain will live
MODEL_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data')
MODEL_PATH = os.path.join(MODEL_DIR, 'malware_classifier.joblib')

def generate_synthetic_data(n_samples=2000):
    """
    Generates synthetic PE file features to train the AI.
    Features: [SizeOfOptionalHeader, Characteristics, MajorLinkerVersion, NumberOfSections, Entropy, 0, 0, 0, 0, 0]
    """
    print("NEURAL GENESIS: Generating synthetic training data...")
    
    X = [] # Features
    y = [] # Labels (0 = Safe, 1 = Malware)

    # 1. Generate "Safe" samples
    # Safe apps usually have low entropy (4.0-6.0) and standard headers
    for _ in range(n_samples // 2):
        header_size = 224 # Standard 32-bit
        characteristics = 258 # Standard EXE
        linker = np.random.randint(6, 14) # Normal linker versions
        sections = np.random.randint(3, 8) # Normal section count
        entropy = np.random.uniform(4.0, 6.2) # Low entropy (not packed)
        
        # Pad with 5 zeros to match our 10-feature vector
        features = [header_size, characteristics, linker, sections, entropy, 0, 0, 0, 0, 0]
        X.append(features)
        y.append(0) # Label: SAFE

    # 2. Generate "Malware" samples
    # Malware is often packed (High Entropy > 7.0) or has weird headers
    for _ in range(n_samples // 2):
        header_size = 224
        characteristics = np.random.randint(8000, 9000) # DLL or System file masquerading
        linker = np.random.randint(0, 5) # Old or weird linker
        sections = np.random.randint(1, 15) # Too few or too many sections
        entropy = np.random.uniform(6.8, 7.99) # HIGH entropy (Encrypted/Packed)
        
        features = [header_size, characteristics, linker, sections, entropy, 0, 0, 0, 0, 0]
        X.append(features)
        y.append(1) # Label: MALWARE

    return np.array(X), np.array(y)

def train_and_save():
    # Ensure data directory exists
    if not os.path.exists(MODEL_DIR):
        os.makedirs(MODEL_DIR)

    # 1. Get Data
    X, y = generate_synthetic_data()
    
    # 2. Initialize the Random Forest Brain
    print("NEURAL GENESIS: Training Random Forest Classifier...")
    clf = RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42)
    
    # 3. Train
    clf.fit(X, y)
    
    # 4. Save
    joblib.dump(clf, MODEL_PATH)
    print(f"✅ SUCCESS: AI Model saved to '{MODEL_PATH}'")
    print("Shield AI is now capable of Predictive Analysis.")

if __name__ == "__main__":
    train_and_save()