import json

from iq.iq import score
from nvd_entry import NVDEntry
# from solver.regexsolver import RegexSolver
from solver.sophisticated_updater import parse_files_to_entries
from utils import get_cve_list, parse_cvs_lists
import sys


def main():
    years = range(2002,2020)

    results = {}
    predicted_entries = parse_files_to_entries()
    for year in years:
        print("Start for year ", year)
        nvd_list = [NVDEntry(e) for e in get_cve_list(year)]
        results[year] = score(nvd_list, ['cwe', 'cpe', 'cvssv2'])
        print(json.dumps(results[year]))
        print()
    #out_file = open('results/iq_results.json', 'w')
    #json.dump(results, out_file)


    #predict_cvss(nvd_list)

    # rs = RegexSolver()
    # updated = rs.solve(nvd_list)


if __name__ == '__main__':
    main()
