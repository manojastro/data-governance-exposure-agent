"""Classifier unit tests: positives, tricky negatives, rollups."""
from __future__ import annotations

from app.classifier.detectors import classify_column, dataset_level


def tags_of(name, samples, dtype="varchar"):
    return [p.tag for p in classify_column(name, dtype, samples)]


def top_proposal(name, samples, dtype="varchar"):
    props = classify_column(name, dtype, samples)
    return props[0] if props else None


# ------------------------------------------------------------- positives ----

def test_email_by_value_and_name():
    p = top_proposal("notes", ["reach bob@corp.example anytime",
                               "alice@example.org asked for a callback"])
    assert p is not None and p.tag == "email"
    assert p.confidence >= 0.6


def test_email_in_free_text_unanchored():
    assert "email" in tags_of("free_note", ["called the customer, left voicemail",
                                            "email bob@corp.example about the case",
                                            "alice@example.org wants a callback"])


def test_phone_formats():
    assert "phone" in tags_of("mobile", ["+1-555-0134-998", "+1-555-0142-771"])
    assert "phone" in tags_of("contact_number", ["(212) 555-0199", "(415) 555-0122"])


def test_fake_gov_id_format():
    p = top_proposal("id_col", ["900-45-6789", "911-22-3333"])
    assert p is not None and p.tag == "gov_id_like"


def test_salary_comma_grouped():
    p = top_proposal("amount_col", ["82,500", "97,300.00"])
    assert p is not None and p.tag == "salary"


def test_bank_iban_style():
    p = top_proposal("acct", ["DE89 3704 0044 0532 0130 00",
                              "DE89 2105 0170 0012 3456 78"])
    assert p is not None and p.tag == "bank_like"


def test_credential_patterns():
    assert "credential_like" in tags_of(
        "config_blob", ["sk-live-abcdef0123456789abcdef", "x" * 40])
    assert "credential_like" in tags_of(
        "conn", ["aws_secret_access_key=AKIAFAKEFAKE", "aws_secret_access_key=AKIAFAKE99"])


def test_business_ids():
    assert "customer_id" in tags_of("cid", ["CUS-000123", "CUS-000456"])
    assert "employee_id" in tags_of("eid", ["EMP-20115", "EMP-20233"])


def test_name_only_hint_when_no_samples():
    p = top_proposal("email_address", [])
    assert p is not None and p.tag == "email"
    assert p.source == "name"


# ------------------------------------------------------------- negatives ----

def test_years_are_not_salary_or_bank():
    t = tags_of("fiscal_year", ["2021", "1999", "2045"])
    assert "salary" not in t and "bank_like" not in t


def test_plain_integers_not_bank():
    t = tags_of("order_total", ["4500", "120", "99"])
    assert "bank_like" not in t


def test_short_numbers_not_bank_or_salary():
    t = tags_of("qty", ["42", "7", "310"])
    assert "bank_like" not in t and "salary" not in t


def test_decimal_order_total_not_salary():
    # 4-digit grouped decimal with leading single digit does not match salary
    t = tags_of("line_amount", ["1,250.99", "3,900.01"])
    assert "salary" not in t


def test_prose_without_email_is_clean():
    t = tags_of("memo", ["customer will call back tomorrow", "no action needed"])
    assert t == []


def test_employee_prefix_is_not_gov_id():
    t = tags_of("ids", ["EMP-20115", "EMP-20233"])
    assert "gov_id_like" not in t


def test_phone_needs_full_format():
    t = tags_of("ref", ["12345", "extension 44"])
    assert "phone" not in t


def test_low_hit_rate_stays_below_threshold():
    # 1 matching sample out of 4 never reaches the confidence floor
    t = tags_of("mixed", ["not an email", "also nothing", "just text",
                          "kim@example.io"])
    assert "email" not in t


# ---------------------------------------------------------------- rollup ----

def test_dataset_level_rollup_prefers_most_sensitive():
    assert dataset_level([["email", "phone"], ["salary"]], None) == "confidential"
    assert dataset_level([["gov_id_like"]], None) == "restricted"
    assert dataset_level([["customer_id"]], None) == "internal"
