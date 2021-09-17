from iq.abstract_metric import Metric
from nvd_entry import NVDEntry
from utils import filter_by_year


class AccuracyMetric(Metric):
    def __init__(self, field_keys: list):
        self.field_keys = field_keys
        # how to insert old dataset

    def score(self, data: list[NVDEntry]):
        values = [entry for entry in data if entry.cvssv3 and entry.predicted_cvssv3]
        score = sum([abs(entry.cvssv3.score() - entry.predicted_cvssv3.score()) for entry in values])
        return (score/len(values)) if values else 0
