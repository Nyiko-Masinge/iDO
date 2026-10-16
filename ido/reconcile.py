import json
import re
from decimal import Decimal, InvalidOperation

def normalize(value):
    if value is None:
        return ""
    text = str(value).strip().casefold()
    return re.sub(r"\s+", " ", text)

def number(value):
    if value is None:
        return None
    cleaned = re.sub(r"[^0-9.\-]", "", str(value).replace(",", ""))
    try:
        return Decimal(cleaned) if cleaned else None
    except InvalidOperation:
        return None

def reconcile(left_rows, right_rows, config):
    """Greedy one-to-one matcher over configured keys with optional amount tolerance."""
    keys = config.get("keys", [])
    amount = config.get("amount_field")
    tolerance = Decimal(str(config.get("tolerance", "0")))
    right_used = set()
    results = []
    for li, left in enumerate(left_rows):
        candidates = []
        for ri, right in enumerate(right_rows):
            if ri in right_used:
                continue
            if not keys or not all(normalize(left.get(k)) == normalize(right.get(k)) for k in keys):
                continue
            if amount:
                lv, rv = number(left.get(amount)), number(right.get(amount))
                if lv is None or rv is None or abs(lv - rv) > tolerance:
                    continue
                diff = abs(lv - rv)
            else:
                diff = Decimal(0)
            candidates.append((diff, ri))
        if candidates:
            diff, ri = min(candidates)
            right_used.add(ri)
            results.append({"left_index": li, "right_index": ri, "status": "matched", "score": 1.0 if not amount else float(1 - min(diff / max(tolerance, Decimal("0.01")), Decimal(1))), "explanation": f"Configured fields matched; amount difference {diff}." if amount else "Configured fields matched exactly.", "left": left, "right": right_rows[ri]})
        else:
            results.append({"left_index": li, "right_index": None, "status": "unmatched_left", "score": 0.0, "explanation": "No unused right-side record matched the configured fields and tolerance.", "left": left, "right": None})
    for ri, right in enumerate(right_rows):
        if ri not in right_used:
            results.append({"left_index": None, "right_index": ri, "status": "unmatched_right", "score": 0.0, "explanation": "No left-side record matched this record.", "left": None, "right": right})
    return results
