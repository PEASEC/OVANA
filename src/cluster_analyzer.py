import json
from collections import defaultdict
import matplotlib.pyplot as plt

from analyzer import Analyzer
from nvd_entry import NVDEntry


class ClusterAnalyzer(Analyzer):
    def __init__(self):
        super().__init__()
        self.cluster_dict_keys = ['cwe', 'cpe', 'path']
        self.all_clusters = None
        self.solved = None
        self.unsolved = None

    def _build_clusters(self, cve_list: list):
        clusters = defaultdict(list)
        for entry in cve_list:
            if any(map(lambda d: 'REJECT' in d, entry.description)):
                continue
            cluster_entry = self._build_cluster_dict(entry)
            ccc_hash = str(hash(json.dumps(cluster_entry, sort_keys=True)))
            clusters[ccc_hash].append(entry)
        self.all_clusters = clusters

    def _build_cluster_dict(self, nvd_entry: NVDEntry):
        return dict((k, v) for (k, v) in nvd_entry.__dict__.items() if k in self.cluster_dict_keys)

    def _build_size_cluster(self):
        clusters_by_size = defaultdict(int)
        for c in self.unsolved:
            clusters_by_size[len(c)] += 1
        return clusters_by_size

    def analyze(self, cve_list: list):
        print('Running cluster analysis')
        print(f'Num CVEs: {len(cve_list)}')
        self._build_clusters(cve_list)
        self.solved = [c for c in self.all_clusters.values() if len(c) == 1]
        self.unsolved = [c for c in self.all_clusters.values() if len(c) > 1]

        clusters_by_size = self._build_size_cluster()
        most = max(clusters_by_size, key=clusters_by_size.get)
        biggest = max(self.unsolved, key=len)

        print(f'total\t: {len(self.all_clusters)}')
        print(f'solved\t: {len(self.solved)}')
        print(f'unsolved: {len(self.unsolved)}')
        print(f'most\t: size {most} with {clusters_by_size[most]}')
        print(f'biggest : {len(biggest)}')

    def plot(self):
        clusters_by_size = self._build_size_cluster()
        plt.bar(clusters_by_size.keys(), clusters_by_size.values())
        plt.show()
