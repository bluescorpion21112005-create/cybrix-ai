from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
from joblib import dump
from data import DATA
import os

texts = [text for text, label in DATA]
labels = [label for text, label in DATA]

X_train, X_test, y_train, y_test = train_test_split(
    texts,
    labels,
    test_size=0.3,
    random_state=42,
    stratify=labels
)

model = Pipeline([
    ("tfidf", TfidfVectorizer(ngram_range=(1, 2), lowercase=True)),
    ("clf", LogisticRegression(max_iter=2000))
])

model.fit(X_train, y_train)

y_pred = model.predict(X_test)

label_names = {
    0: "NORMAL",
    1: "SUSPICIOUS",
    2: "SQL_ERROR"
}

print("=== Classification Report ===")
print(classification_report(
    y_test,
    y_pred,
    target_names=[label_names[0], label_names[1], label_names[2]]
))

print("=== Confusion Matrix ===")
print(confusion_matrix(y_test, y_pred))

tests = [
    "mysql error: you have an error in your SQL syntax",
    "Welcome to the dashboard",
    "ORA-01756 quoted string not properly terminated",
    "Search results loaded normally",
    "Internal server error",
    "Query execution failed"
]

print("\n=== Manual Tests ===")
for text in tests:
    pred = model.predict([text])[0]
    probs = model.predict_proba([text])[0]
    print(f"TEXT: {text}")
    print(f"PREDICTION: {label_names[pred]}")
    print(f"PROBABILITIES: NORMAL={probs[0]:.3f}, SUSPICIOUS={probs[1]:.3f}, SQL_ERROR={probs[2]:.3f}")
    print("-" * 60)

os.makedirs("models", exist_ok=True)
dump(model, "models/sql_error_model.joblib")
print("\nModel saved to models/sql_error_model.joblib")