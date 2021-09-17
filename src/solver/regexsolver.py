from solver.solver import Solver
from nvd_entry import NVDEntry
import re
import copy


class RegexSolver(Solver):
    def solve_by_path(self, nvd_dataset: list):
        return self._regex_solve(nvd_dataset, r'[A-Za-z][\w\/]+\.[A-Za-z]+', 'path')

    def solve_by_zdi(self, nvd_dataset: list):
        return self._regex_solve(nvd_dataset, r'ZDI-CAN-[0-9]{1,24}', 'zdi')

    def solve_by_cwe(self, nvd_dataset: list):
        return self._regex_solve(nvd_dataset, r'CWE-[0-9]+', 'cwe')

    def _regex_solve(self, nvd_dataset: list, regex: str, nvd_key: str):
        updated = []
        for entry in nvd_dataset:
            copied = copy.copy(entry)
            found = self._regex_search(copied, regex)
            if found:
                if copied.__dict__[nvd_key] == None:
                    copied.__dict__[nvd_key] = list(sorted(found))
                else:
                    copied.__dict__[nvd_key] = list(set(copied.__dict__[nvd_key].union(set(sorted(found)))))
            updated.append(copied)
        return updated

    def solve(self, nvd_dataset: list):
        return self.solve_by_cwe(self.solve_by_path(nvd_dataset))

    @staticmethod
    def _regex_search(entry: NVDEntry, regex: str):
        return set(fn for desc in entry.description for fn in re.findall(regex, desc))
