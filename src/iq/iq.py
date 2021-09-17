from iq import completeness_metric, uniqueness_metric, accuracy_metric
from nvd_entry import NVDEntry
from solver.sophisticated_updater import update_db
from utils import filter_by_year, filter_list_by_year


def score(nvd_dataset: list, keys: list):
    cm = completeness_metric.CompletenessMetric(keys)
    um = uniqueness_metric.UniquenessMetric(keys)
    am = accuracy_metric.AccuracyMetric(['cvssv3'])

    cm_score = cm.score(nvd_dataset)
    um_score = um.score(nvd_dataset)
    am_score = am.score(nvd_dataset)

    return {'cm_score': cm_score, 'um_score': um_score, 'am_score': am_score}
