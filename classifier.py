"""
classifier.py
---------------
TF-IDF + Logistic Regression phishing-intent text classifier.

Loads phishing_classifier.joblib if present; otherwise trains a small
in-memory model from TRAINING_SAMPLES below on first run (and can
optionally save it back to disk). Keeping a bundled fallback dataset
means the app never breaks just because the .joblib file didn't ship,
and it makes the model retrainable/extensible -- add more rows to
TRAINING_SAMPLES and re-run train_and_save() to improve it.
"""

import os
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline

try:
    import joblib
    _JOBLIB_AVAILABLE = True
except ImportError:
    _JOBLIB_AVAILABLE = False

MODEL_PATH = os.path.join(os.path.dirname(__file__), "phishing_classifier.joblib")

# label: 1 = phishing, 0 = legitimate. Extend this list freely.
TRAINING_SAMPLES = [
    ("urgent verify your account now or it will be suspended click here immediately", 1),
    ("your account will be permanently closed unless you confirm your identity within 24 hours", 1),
    ("congratulations you have won a prize claim your reward now click this link", 1),
    ("dear customer your package could not be delivered pay a small customs fee to release it", 1),
    ("your password expires today re-authenticate now to avoid losing mailbox access", 1),
    ("action required kyc verification pending click below to avoid account suspension", 1),
    ("limited time offer verify your bank details to receive your refund", 1),
    ("security alert unusual login detected verify your identity immediately or lose access", 1),
    ("your invoice is attached please review at your convenience", 0),
    ("thank you for your order your package has shipped and will arrive in 3 to 5 days", 0),
    ("this is your monthly account statement no action is required", 0),
    ("reminder your subscription renews next week you can manage it from your account settings", 0),
    ("hi team please find attached the meeting notes from today's call", 0),
    ("your recent sign-in was from a new device if this was you no action is needed", 0),
    ("here is the report you asked for let me know if you have questions", 0),
    ("your order confirmation number is included below for your records", 0),
]


def _build_pipeline():
    return Pipeline([
        ("tfidf", TfidfVectorizer(max_features=20000, stop_words="english", ngram_range=(1, 2))),
        ("clf", LogisticRegression(max_iter=1000)),
    ])


def train_and_save():
    texts = [t for t, _ in TRAINING_SAMPLES]
    labels = [l for _, l in TRAINING_SAMPLES]
    pipe = _build_pipeline()
    pipe.fit(texts, labels)
    if _JOBLIB_AVAILABLE:
        joblib.dump(pipe, MODEL_PATH)
    return pipe


def load_model():
    if _JOBLIB_AVAILABLE and os.path.exists(MODEL_PATH):
        try:
            return joblib.load(MODEL_PATH)
        except Exception:
            pass
    return train_and_save()


_MODEL = None


def get_model():
    global _MODEL
    if _MODEL is None:
        _MODEL = load_model()
    return _MODEL


def predict_phishing_probability(text: str) -> float:
    model = get_model()
    if not text.strip():
        return 0.0
    proba = model.predict_proba([text])[0]
    # class order matches TRAINING_SAMPLES label order fit by sklearn (classes_ attribute)
    classes = list(model.named_steps["clf"].classes_)
    phishing_idx = classes.index(1)
    return float(proba[phishing_idx])


def explain(text: str, top_n=8):
    """Returns the top N TF-IDF terms present in `text` that most influenced
    the phishing prediction, for an explainability panel on the dashboard."""
    model = get_model()
    if not text.strip():
        return []
    tfidf = model.named_steps["tfidf"]
    clf = model.named_steps["clf"]
    vec = tfidf.transform([text])
    feature_names = tfidf.get_feature_names_out()
    coefs = clf.coef_[0]
    nonzero_idx = vec.nonzero()[1]
    scored = [(feature_names[i], vec[0, i] * coefs[i]) for i in nonzero_idx]
    scored.sort(key=lambda x: x[1], reverse=True)
    return scored[:top_n]


if __name__ == "__main__":
    m = train_and_save()
    print("Trained. Example:", predict_phishing_probability(
        "urgent verify your account now or it will be suspended"))
