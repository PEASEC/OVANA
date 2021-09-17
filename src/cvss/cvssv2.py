import enum

from cvss.utils import get_enum_first_char


class AccessVector(enum.Enum):
    LOCAL = 0.395
    ADJACENT_NETWORK = 0.646
    NETWORK = 1.0


class AccessComplexity(enum.Enum):
    HIGH = 0.35
    MEDIUM = 0.61
    LOW = 0.71


class Authentication(enum.Enum):
    MULTIPLE = 0.45
    SINGLE = 0.56
    NONE = 0.704


class ConfidentialityImpact(enum.Enum):
    NONE = 0
    PARTIAL = 0.275
    COMPLETE = 0.66


class IntegrityImpact(enum.Enum):
    NONE = 0
    PARTIAL = 0.275
    COMPLETE = 0.66


class AvailabilityImpact(enum.Enum):
    NONE = 0
    PARTIAL = 0.275
    COMPLETE = 0.66


class CVSSV2:
    def __init__(self, cvss_entry: dict):
        self.accessComplexity = AccessComplexity[cvss_entry['accessComplexity']]
        self.accessVector = AccessVector[cvss_entry['accessVector']]
        self.authentication = Authentication[cvss_entry['authentication']]
        self.availability_impact = AvailabilityImpact[cvss_entry['availabilityImpact']]
        self.confidentiality_impact = ConfidentialityImpact[cvss_entry['confidentialityImpact']]
        self.integrity_impact = AvailabilityImpact[cvss_entry['integrityImpact']]

    def vector(self):
        av = get_enum_first_char(self.accessVector)
        ac = get_enum_first_char(self.accessComplexity)
        au = get_enum_first_char(self.authentication)
        ci = get_enum_first_char(self.confidentiality_impact)
        ii = get_enum_first_char(self.integrity_impact)
        ai = get_enum_first_char(self.availability_impact)
        return f'AV:{av}/AV:{ac}/Au:{au}/C:{ci}/I:{ii}/A:{ai}'

    def score(self):
        impact = 10.41 * (1 -
                          (1 - self.confidentiality_impact.value) *
                          (1 - self.integrity_impact.value) *
                          (1 - self.availability_impact.value))
        exploitability = 20 * self.accessVector.value * self.accessComplexity.value * self.authentication.value
        f_impact = 0 if impact == 0 else 1.176
        return round(((0.6 * impact) + (0.4 * exploitability) - 1.5) * f_impact, 1)

    def __str__(self):
        return self.vector()
    
    def __repr__(self):
        return f'{self.vector()} - [{self.score()}]'
