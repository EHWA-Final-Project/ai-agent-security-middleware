import pytest

from security.measurement import percentile, summarize


def test_nearest_rank_percentiles():
    values = list(range(1, 101))

    assert percentile(values, 50) == 50
    assert percentile(values, 95) == 95
    assert percentile(values, 100) == 100


def test_percentile_ignores_input_order():
    assert percentile([5.0, 1.0, 3.0, 2.0, 4.0], 50) == 3.0


def test_percentile_returns_an_observed_value():
    values = [1.0, 2.0, 10.0]

    assert percentile(values, 95) in values


def test_single_value():
    assert percentile([7.0], 50) == percentile([7.0], 95) == 7.0


def test_few_samples_make_p95_equal_the_max():
    values = [1.0, 2.0, 3.0, 4.0, 5.0]

    assert percentile(values, 95) == max(values)


@pytest.mark.parametrize("p", [0, -1, 100.1])
def test_invalid_percentile_rejected(p):
    with pytest.raises(ValueError):
        percentile([1.0], p)


def test_empty_input_rejected():
    with pytest.raises(ValueError):
        percentile([], 50)
    with pytest.raises(ValueError):
        summarize([])


def test_summarize():
    s = summarize([1.0, 2.0, 3.0, 4.0])

    assert s == {"n": 4.0, "avg": 2.5, "p50": 2.0, "p95": 4.0, "max": 4.0}
