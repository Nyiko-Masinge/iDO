import re
from collections import Counter, defaultdict
from datetime import date, datetime
from decimal import Decimal, InvalidOperation


def normalize(value):
    if value is None:
        return ""
    return re.sub(r"\s+", " ", str(value).strip().casefold())


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
        text = text[:text.rfind(",")].replace(",", "") + ("." + tail if len(tail) in {1, 2} else tail)
    elif text.count(".") > 1:
        tail = text.rsplit(".", 1)[-1]
        text = text[:text.rfind(".")].replace(".", "") + ("." + tail if len(tail) in {1, 2} else tail)
    if negative and not text.startswith("-"):
        text = "-" + text
    try:
        return Decimal(text) if text else None
    except InvalidOperation:
        return None


def parsed_date(value):
    if value is None or not str(value).strip():
        return None
    text = str(value).strip()
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00")).date()
    except ValueError:
        for fmt in ("%Y/%m/%d", "%d/%m/%Y", "%m/%d/%Y", "%d-%m-%Y", "%Y%m%d"):
            try:
                return datetime.strptime(text[:10], fmt).date()
            except ValueError:
                pass
    return None


def reconcile(left_rows, right_rows, config):
    """Deterministic one-to-one matcher with reusable data-quality controls."""
    mappings = config.get("key_mappings") or [{"left": key, "right": key} for key in config.get("keys", [])]
    amount = config.get("amount_mapping")
    if not amount and config.get("amount_field"):
        amount = {"left": config["amount_field"], "right": config["amount_field"]}
    tolerance = Decimal(str(config.get("tolerance", "0")))
    date_window = config.get("date_window") or {}
    date_enabled = bool(date_window.get("left") and date_window.get("right"))
    window_days = int(date_window.get("days", 0))
    detect_duplicates = config.get("duplicate_detection", True)
    partial = config.get("partial_matching") or {}
    partial_enabled = bool(partial.get("enabled")) and len(mappings) > 1
    min_key_ratio = float(partial.get("minimum_key_ratio", 0.75))
    min_key_matches = max(1, int(len(mappings) * min_key_ratio + 0.999999))

    alias_index = defaultdict(list)
    for alias in config.get("aliases", []):
        alias_index[(alias["left_field"], alias["right_field"], normalize(alias.get("right_value")))].append(alias)

    def values(row, side):
        result = []
        for mapping in mappings:
            field = mapping[side]
            value = normalize(row.get(field))
            if side == "right":
                for alias in alias_index.get((mapping["left"], mapping["right"], value), []):
                    if all(normalize(row.get(ctx["right_field"])) == ctx["right_value"] for ctx in alias.get("context", [])):
                        value = normalize(alias["left_value"])
                        break
            result.append(value)
        return tuple(result)

    left_keys = [values(row, "left") for row in left_rows]
    right_keys = [values(row, "right") for row in right_rows]
    left_counts, right_counts = Counter(left_keys), Counter(right_keys)
    invalid_left_amount = [amount is not None and number(row.get(amount["left"])) is None for row in left_rows]
    invalid_right_amount = [amount is not None and number(row.get(amount["right"])) is None for row in right_rows]
    left_dates = [parsed_date(row.get(date_window.get("left"))) if date_enabled else None for row in left_rows]
    right_dates = [parsed_date(row.get(date_window.get("right"))) if date_enabled else None for row in right_rows]
    duplicate_left = {key for key, count in left_counts.items() if count > 1 and key and all(key)}
    duplicate_right = {key for key, count in right_counts.items() if count > 1 and key and all(key)}
    duplicate_keys = duplicate_left | duplicate_right if detect_duplicates else set()

    right_exact = defaultdict(list)
    right_partial = defaultdict(list)
    for ri, key in enumerate(right_keys):
        if not key or not all(key) or invalid_right_amount[ri] or (detect_duplicates and key in duplicate_keys):
            continue
        right_exact[key].append(ri)
        if partial_enabled:
            for ki, value in enumerate(key):
                right_partial[(ki, value)].append(ri)

    used = set()
    results = []
    for li, left in enumerate(left_rows):
        key = left_keys[li]
        base = {"left_index": li, "right_index": None, "status": "unmatched_left", "score": 0.0,
                "left": left, "right": None, "exception_category": None}
        category = None
        if not key or not all(key):
            category = "missing_key"
        elif date_enabled and left_dates[li] is None:
            category = "invalid_date"
        elif invalid_left_amount[li]:
            category = "invalid_amount"
        elif detect_duplicates and key in duplicate_keys:
            category = "duplicate_both_sides" if key in duplicate_left and key in duplicate_right else ("duplicate_left" if key in duplicate_left else "duplicate_right")
        else:
            candidates = right_exact.get(key, [])
            exact_matches = []
            outside_date = False
            for ri in candidates:
                if ri in used:
                    continue
                if date_enabled:
                    if left_dates[li] is None or right_dates[ri] is None:
                        continue
                    if abs((left_dates[li] - right_dates[ri]).days) > window_days:
                        outside_date = True
                        continue
                if amount:
                    diff = abs(number(left.get(amount["left"])) - number(right_rows[ri].get(amount["right"])))
                    if diff > tolerance:
                        continue
                else:
                    diff = Decimal(0)
                exact_matches.append((diff, ri))
            selected = min(exact_matches, default=None)
            partial_match = False
            if selected is None and partial_enabled:
                candidate_counts = Counter()
                for ki, value in enumerate(key):
                    if value:
                        candidate_counts.update(set(right_partial.get((ki, value), [])))
                scored = []
                for ri, key_hits in candidate_counts.items():
                    if ri in used or key_hits < min_key_matches:
                        continue
                    if date_enabled and (left_dates[li] is None or right_dates[ri] is None or abs((left_dates[li] - right_dates[ri]).days) > window_days):
                        outside_date = True
                        continue
                    if amount:
                        diff = abs(number(left.get(amount["left"])) - number(right_rows[ri].get(amount["right"])))
                        if diff > tolerance:
                            continue
                    else:
                        diff = Decimal(0)
                    scored.append((key_hits, diff, ri))
                if scored:
                    best_hits = max(item[0] for item in scored)
                    best = [item for item in scored if item[0] == best_hits]
                    if len(best) == 1:
                        hits, diff, ri = best[0]
                        selected = (diff, ri)
                        partial_match = True
                    else:
                        category = "ambiguous_partial_match"
            if selected:
                diff, ri = selected
                used.add(ri)
                match_score = (best_hits / len(mappings)) if partial_match else (1.0 if not amount else float(1 - min(diff / max(tolerance, Decimal("0.01")), Decimal(1))))
                base.update(right_index=ri, status="matched", score=match_score,
                            explanation=(f"Partial match: {best_hits} of {len(mappings)} configured key fields matched; amount difference {diff}." if partial_match else (f"Configured fields matched; amount difference {diff}." if amount else "Configured fields matched exactly.")),
                            right=right_rows[ri], exception_category="partial_match" if partial_match else None)
                results.append(base)
                continue
            if category is None:
                category = "date_outside_window" if outside_date else "no_candidate_match"
        base["exception_category"] = category
        base["explanation"] = {
            "missing_key": "One or more configured key fields are blank.",
            "invalid_date": "Date is missing or could not be parsed using the configured date-window rule.",
            "invalid_amount": "Amount is missing or cannot be parsed as a number.",
            "duplicate_left": "This configured key appears more than once on the left; automatic matching was withheld.",
            "duplicate_right": "This configured key appears more than once on the right; automatic matching was withheld.",
            "duplicate_both_sides": "This configured key is duplicated on both sides; automatic matching was withheld.",
            "date_outside_window": f"Candidate record is outside the configured {window_days}-day date window or its date is invalid.",
            "ambiguous_partial_match": "Several records have the same best partial-key score; automatic matching was withheld.",
            "no_candidate_match": "No unused record matched the configured fields, amount tolerance, and date window.",
        }[category]
        results.append(base)

    for ri, right in enumerate(right_rows):
        if ri in used:
            continue
        key = right_keys[ri]
        if not key or not all(key):
            category = "missing_key"
        elif date_enabled and right_dates[ri] is None:
            category = "invalid_date"
        elif invalid_right_amount[ri]:
            category = "invalid_amount"
        elif detect_duplicates and key in duplicate_keys:
            category = "duplicate_both_sides" if key in duplicate_left and key in duplicate_right else ("duplicate_left" if key in duplicate_left else "duplicate_right")
        else:
            category = "no_candidate_match"
        results.append({"left_index": None, "right_index": ri, "status": "unmatched_right", "score": 0.0,
                        "exception_category": category, "explanation": "No left-side record matched this record. " + category.replace("_", " ") + ".",
                        "left": None, "right": right})
    return results
