import re
from bisect import bisect_left
from collections import defaultdict
from decimal import Decimal, InvalidOperation

def normalize(value):
    if value is None:
        return ""
    text = str(value).strip().casefold()
    return re.sub(r"\s+", " ", text)

def number(value):
    if value is None:
        return None
    text = str(value).strip()
    negative = text.startswith("(") and text.endswith(")")
    text = re.sub(r"[^0-9,.+\-]", "", text.strip("()"))
    if "," in text and "." in text:
        decimal_separator = "," if text.rfind(",") > text.rfind(".") else "."
        thousands_separator = "." if decimal_separator == "," else ","
        text = text.replace(thousands_separator, "").replace(decimal_separator, ".")
    elif "," in text:
        tail = text.rsplit(",", 1)[-1]
        if len(tail) in {1, 2}:
            text = text[:text.rfind(",")].replace(",", "") + "." + tail
        else:
            text = text.replace(",", "")
    elif text.count(".") > 1:
        tail = text.rsplit(".", 1)[-1]
        text = text[:text.rfind(".")].replace(".", "") + ("." + tail if len(tail) in {1, 2} else tail)
    if negative and not text.startswith("-"):
        text = "-" + text
    try:
        return Decimal(text) if text else None
    except InvalidOperation:
        return None

def reconcile(left_rows, right_rows, config):
    """Greedy one-to-one matcher over configured keys with optional amount tolerance."""
    mappings = config.get("key_mappings") or [{"left": key, "right": key} for key in config.get("keys", [])]
    amount = config.get("amount_mapping")
    if not amount and config.get("amount_field"):
        amount = {"left": config["amount_field"], "right": config["amount_field"]}
    tolerance = Decimal(str(config.get("tolerance", "0")))
    alias_index = defaultdict(list)
    for alias in config.get("aliases", []):
        alias_index[(alias["left_field"], alias["right_field"], normalize(alias.get("right_value")))].append(alias)

    def right_key(row):
        values = []
        for mapping in mappings:
            value = normalize(row.get(mapping["right"]))
            for alias in alias_index.get((mapping["left"], mapping["right"], value), []):
                if all(normalize(row.get(context["right_field"])) == context["right_value"] for context in alias.get("context", [])):
                    value = normalize(alias["left_value"])
                    break
            values.append(value)
        return tuple(values)

    right_groups = defaultdict(list)
    for ri, right in enumerate(right_rows):
        key = right_key(right)
        if not key or any(value == "" for value in key):
            continue
        value = number(right.get(amount["right"])) if amount else None
        if amount and value is None:
            continue
        right_groups[key].append((value, ri))
    for group in right_groups.values():
        group.sort(key=lambda item: (item[0] if item[0] is not None else Decimal(0), item[1]))
    right_values = {key: [item[0] for item in group] for key, group in right_groups.items()}
    right_used = set()
    results = []
    for li, left in enumerate(left_rows):
        key = tuple(normalize(left.get(m["left"])) for m in mappings)
        group = right_groups.get(key, [])
        match = None
        diff = Decimal(0)
        if not key or any(value == "" for value in key):
            group = []
        elif amount:
            left_amount = number(left.get(amount["left"]))
            values = right_values.get(key, [])
            if left_amount is not None:
                pos = bisect_left(values, left_amount)
                lo, hi = pos - 1, pos
                while lo >= 0 or hi < len(group):
                    left_diff = abs(group[lo][0] - left_amount) if lo >= 0 and group[lo][0] is not None else None
                    right_diff = abs(group[hi][0] - left_amount) if hi < len(group) and group[hi][0] is not None else None
                    if left_diff is None:
                        lo -= 1
                        continue
                    if right_diff is None:
                        hi += 1
                        continue
                    if left_diff <= right_diff:
                        candidate_diff, ri = left_diff, group[lo][1]
                        lo -= 1
                    else:
                        candidate_diff, ri = right_diff, group[hi][1]
                        hi += 1
                    if candidate_diff > tolerance:
                        break
                    if ri not in right_used:
                        match, diff = ri, candidate_diff
                        break
        else:
            for _, ri in group:
                if ri not in right_used:
                    match = ri
                    break
        if match is not None:
            ri = match
            right_used.add(ri)
            results.append({"left_index": li, "right_index": ri, "status": "matched", "score": 1.0 if not amount else float(1 - min(diff / max(tolerance, Decimal("0.01")), Decimal(1))), "explanation": f"Configured fields matched; amount difference {diff}." if amount else "Configured fields matched exactly.", "left": left, "right": right_rows[ri]})
        else:
            results.append({"left_index": li, "right_index": None, "status": "unmatched_left", "score": 0.0, "explanation": "No unused right-side record matched the configured fields and tolerance.", "left": left, "right": None})
    for ri, right in enumerate(right_rows):
        if ri not in right_used:
            results.append({"left_index": None, "right_index": ri, "status": "unmatched_right", "score": 0.0, "explanation": "No left-side record matched this record.", "left": None, "right": right})
    return results
