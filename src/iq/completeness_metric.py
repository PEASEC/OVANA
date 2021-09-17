from iq.abstract_metric import Metric
from nvd_entry import NVDEntry
from utils import filter_by_year


class CompletenessMetric(Metric):
    def __init__(self, field_keys: list):
        self.field_keys = field_keys

    def _completeness(self, nvd_entry: NVDEntry):
        return sum(1 for field_key in self.field_keys if field_key not in nvd_entry.__dict__ or not nvd_entry.__dict__[field_key])

    def score(self, nvd_dataset: list):
        numerator = sum(self._completeness(nvd_entry) for nvd_entry in nvd_dataset)
        return numerator / len(nvd_dataset)
