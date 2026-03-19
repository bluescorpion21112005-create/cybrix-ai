from pprint import pprint
from lab_analyzer import analyze_case

result = analyze_case("lab_cases/case1")

if not result.get("ok"):
    print("ERROR:", result.get("error"))
else:
    print("CASE:", result["case"])
    print("TITLE:", result.get("metadata", {}).get("title"))
    print("BASELINE:", result["baseline"])
    print("SUMMARY:", result["summary"])
    print("TOP PAYLOAD:", result["top_payload"]["file"] if result["top_payload"] else "None")
    print("-" * 60)
    pprint(result["payloads"])