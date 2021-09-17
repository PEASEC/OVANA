from cvss.cvssv3 import CVSSV3
from nvd_entry import NVDEntry
from collections import defaultdict

translate_values = {
    'AV': {'N': 'NETWORK', 'A': 'ADJACENT_NETWORK', 'L': 'LOCAL', 'P': 'PHYSICAL'},
    'AC': {'L': 'LOW', 'H': 'HIGH'},
    'PR': {'N': 'NONE', 'L': 'LOW', 'H': 'HIGH'},
    'UI': {'N': 'NONE', 'R': 'REQUIRED'},
    'SC': {'C': 'CHANGED', 'U': 'UNCHANGED'},
    'CI': {'H': 'HIGH', 'L': 'LOW', 'N': 'NONE'},
    'II': {'H': 'HIGH', 'L': 'LOW', 'N': 'NONE'},
    'AI': {'H': 'HIGH', 'L': 'LOW', 'N': 'NONE'}
}

translate_keys = {
    'AV': 'attackVector',
    'AC': 'attackComplexity',
    'PR': 'privilegesRequired',
    'UI': 'userInteraction',
    'SC': 'scope',
    'CI': 'confidentialityImpact',
    'II': 'integrityImpact',
    'AI': 'availabilityImpact'
}

files = ['nvd-files/all_cves_1_all_tags.csv.xls', 'nvd-files/all_cves_2_all_tags.csv.xls']


def _get_tags(entry: list):
    for l in entry:
        token, tags, cve_id = l.split()
        for t in tags.split(','):
            yield t, token


def _parse_for_tags(entry: list):
    parsed = defaultdict(list)
    for tag, token in _get_tags(entry):
        parsed[tag].append(token)
    return parsed


def _extract_cvss_parameters(parsed_entry: dict):
    cvss_parameters = {}
    for key in [key for key in parsed_entry if ':' in key]:
        param, value = key.split(':')
        cvss_parameters[translate_keys[param]] = translate_values[param][value]
    return cvss_parameters


def _set_tags(nvd_entry: NVDEntry, parsed: dict):
    cvss_parameters = _extract_cvss_parameters(parsed)

    nvd_entry.vulnerable_function = set(parsed.get('VF', []))
    nvd_entry.path = set(parsed.get('VP', []))
    nvd_entry.weakness = parsed.get('W', [])
    nvd_entry.predicted_cvssv3 = CVSSV3(cvss_parameters, nvd_entry.cvssv3.__dict__ if nvd_entry.cvssv3 else None)


def update_db(nvd_dataset: list, predicted_entries: list):
    dataset_dict = {e.id: e for e in nvd_dataset}
    for e in predicted_entries:
        parsed = _parse_for_tags(e)
        e_id = e[0].split()[2]
        referred = dataset_dict.get(e_id)
        if referred:
            _set_tags(referred, parsed)
            yield referred


def parse_files_to_entries():
    content = ''.join(open(f, encoding="ISO-8859-1").read() for f in files)
    return [e.splitlines() for e in content.split('\n\n') if e]
