from predictor import predict_text

with open("samples/sql_error_sample.html", "r", encoding="utf-8") as f:
    content = f.read()

result = predict_text(content)

print("Prediction:", result["label"])
print(
    f'Probabilities -> NORMAL={result["normal"]:.3f}, '
    f'SUSPICIOUS={result["suspicious"]:.3f}, '
    f'SQL_ERROR={result["sql_error"]:.3f}'
)