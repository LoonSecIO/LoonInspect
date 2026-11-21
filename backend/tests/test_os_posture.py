from datetime import date

from app.core.sofa import assessment, catalog_for

CATALOG = {
    "models": {"Mac1,1": [14, 15]},
    "branches": {"15": {"version": "15.7", "builds": ["24H1", "24H2"]}, "26": {"version": "26.1", "builds": ["25B1"]}},
}


def test_patch_currency_and_hardware_are_independent():
    assert assessment("15.7", "24H2", "Mac1,1", "26", CATALOG) == ("current", "15.7", "incompatible")
    assert assessment("15.6", "24F1", "Mac1,1", "15", CATALOG) == ("available", "15.7", "compatible")
    assert assessment("15.7", "unlisted", "new-model", "15", CATALOG) == ("unknown", "15.7", "unknown")
    assert assessment("15.7", None, "Mac1,1", "15", CATALOG)[2] == "unknown"


def test_old_dates_never_inherit_future_catalog():
    assert catalog_for(date(2001, 1, 1)) is None
