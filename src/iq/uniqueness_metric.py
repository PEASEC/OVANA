import json
from collections import defaultdict

import jsonpickle

from nvd_entry import NVDEntry
from iq.abstract_metric import Metric
from utils import filter_by_year


class UniquenessMetric(Metric):
    def __init__(self, nvd_keys: list = None):
        super().__init__()
        self.cluster_dict_keys: list = nvd_keys

    def build_clusters(self, nvd_dataset: list):
        clusters = defaultdict(list)
        jsonpickle.set_encoder_options('json', sort_keys=True)
        for entry in nvd_dataset:
            cluster_entry_dict = self._build_cluster_entry_dict(entry)
            cluster_dict_string = str(jsonpickle.encode(cluster_entry_dict))
            clusters[cluster_dict_string].append(entry)
        return clusters

    def _build_cluster_entry_dict(self, nvd_entry: NVDEntry):
        return dict((k, v) for (k, v) in nvd_entry.__dict__.items() if k in self.cluster_dict_keys)

    def score(self, nvd_dataset: list):
        clusters = self.build_clusters(nvd_dataset)
        numerator = sum(len(c) ** 2 for c in clusters.values())
        return numerator / len(clusters) - 1
