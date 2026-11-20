import pytest

from runtime import AnalysisBusyError, analysis_slot


def test_concurrency_limit_rejects_and_recovers():
    with analysis_slot(1):
        with pytest.raises(AnalysisBusyError):
            with analysis_slot(1):
                pass
    with analysis_slot(1):
        pass
