from abc import ABC, abstractmethod


class Solver(ABC):
    @abstractmethod
    def solve(self, nvd_dataset: list) -> list:
        pass