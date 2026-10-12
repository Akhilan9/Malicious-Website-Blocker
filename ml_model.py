import os
import math
import pickle
import pandas as pd
import numpy as np
from urllib.parse import urlparse
from sklearn.ensemble import RandomForestClassifier
from config import BASE_DIR

MODEL_PATH = os.path.join(BASE_DIR, "url_ml_model.pkl")

def get_entropy(text):
    """Calculate the Shannon entropy of a string."""
    if not text:
        return 0
    entropy = 0
    for x in set(text):
        p_x = float(text.count(x)) / len(text)
        entropy += - p_x * math.log2(p_x)
    return entropy

def extract_features(url):
    """
    Extract numerical features from a URL for ML classification.
    """
    if not url.startswith('http'):
        url = 'http://' + url
        
    parsed = urlparse(url)
    domain = parsed.netloc.split(":")[0]
    path = parsed.path
    
    features = {
        'url_length': len(url),
        'domain_length': len(domain),
        'path_length': len(path),
        'num_dots': url.count('.'),
        'num_hyphens': url.count('-'),
        'num_underscores': url.count('_'),
        'num_slash': url.count('/'),
        'num_question': url.count('?'),
        'num_equal': url.count('='),
        'num_at': url.count('@'),
        'num_ampersand': url.count('&'),
        'num_exclamation': url.count('!'),
        'num_space': url.count(' ') + url.count('%20'),
        'entropy': get_entropy(url),
        'is_ip': 1 if parsed.hostname and parsed.hostname.replace('.', '').isnumeric() else 0
    }
    return features

def train_dummy_model():
    """
    Train a basic Random Forest model on synthetic data and save it.
    In a real-world scenario, this would be trained on a large dataset like PhishTank.
    """
    # Create synthetic dataset
    data = [
        # Safe URLs
        ("https://google.com", 0), ("https://github.com", 0), ("https://wikipedia.org", 0),
        ("https://youtube.com/watch?v=123", 0), ("https://microsoft.com", 0),
        ("http://localhost:8000", 0), ("https://amazon.com/products/1", 0),
        
        # Malicious/Phishing URLs (synthetic patterns)
        ("http://192.168.1.1/login.php", 1), ("http://secure-update.paypal.com-verification.xyz", 1),
        ("http://free-iphone-winner-click-here.tk", 1), ("https://bankofamerica.secure-login-34.com", 1),
        ("http://10.0.0.5/admin/login?user=admin&pass=1234", 1),
        ("http://support.apple.com-verify.ga/login", 1),
        ("http://xn--80ak6aa92e.com", 1)
    ]
    
    df = pd.DataFrame(data, columns=['url', 'label'])
    
    # Extract features for training
    features_list = [extract_features(url) for url in df['url']]
    X = pd.DataFrame(features_list)
    y = df['label']
    
    # Train model
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X, y)
    
    # Save model
    with open(MODEL_PATH, 'wb') as f:
        pickle.dump(model, f)
        
    return model

def load_or_train_model():
    if os.path.exists(MODEL_PATH):
        try:
            with open(MODEL_PATH, 'rb') as f:
                return pickle.load(f)
        except Exception:
            return train_dummy_model()
    else:
        return train_dummy_model()

# Lazy-loaded model
rf_model = None

def get_model():
    global rf_model
    if rf_model is None:
        rf_model = load_or_train_model()
    return rf_model

def predict_url_safety(url):
    """
    Predict if a URL is malicious using the ML model.
    Returns: (is_malicious (bool), confidence (float))
    """
    try:
        features = extract_features(url)
        X = pd.DataFrame([features])
        
        model = get_model()
        
        # Predict probability
        probs = model.predict_proba(X)[0]
        # probs[1] is probability of being malicious (label 1)
        
        confidence = round(probs[1] * 100, 2)
        is_malicious = probs[1] > 0.5
        
        return is_malicious, confidence
    except Exception as e:
        print(f"ML Error: {e}")
        return False, 0.0
