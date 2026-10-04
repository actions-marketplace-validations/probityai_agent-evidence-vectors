"""Negative-control reader that treats every reported relationship as matched."""

import json
import sys

bundle = json.load(sys.stdin)
rows = [
    {
        "position": f"e{control_index}.a{assessment_index}",
        "method": "matched",
        "executor": "match",
        "executor_source": "explicit" if "executor" in assessment else "log_author",
        "reported_result": assessment["result"],
    }
    for control_index, evaluation in enumerate(bundle["log"]["evaluations"])
    for assessment_index, assessment in enumerate(evaluation["assessment-logs"])
]
print(json.dumps({"shape_errors": [], "rows": rows, "conflicts": []}))
