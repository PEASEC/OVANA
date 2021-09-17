import enum
import math

from cvss.utils import get_enum_first_char


class AttackVector(enum.Enum):
    PHYSICAL = 0.2
    LOCAL = 0.55
    ADJACENT_NETWORK = 0.62
    NETWORK = 0.85


class AttackComplexity(enum.Enum):
    HIGH = 0.44
    LOW = 0.77


class PrivilegesRequired(enum.Enum):
    NONE = (0.85, 0.85)  # 0.85 in both cases
    LOW = (0.62, 0.68)  # 0.68 if scope changed
    HIGH = (0.27, 0.5)  # 0.5 if scope changed


class UserInteraction(enum.Enum):
    NONE = 0.85
    REQUIRED = 0.62


class Scope(enum.Enum):
    UNCHANGED = 0
    CHANGED = 1


class ConfidentialityImpact(enum.Enum):
    NONE = 0
    LOW = 0.22
    HIGH = 0.56


class IntegrityImpact(enum.Enum):
    NONE = 0
    LOW = 0.22
    HIGH = 0.56


class AvailabilityImpact(enum.Enum):
    NONE = 0
    LOW = 0.22
    HIGH = 0.56


class CVSSV3:
    def __init__(self, cvss_dict: dict, old_cvss_dict=None):
        if old_cvss_dict is None:
            old_cvss_dict = {}
        else:
            old_cvss_dict = {key:str(value).split('.')[1] for key, value in old_cvss_dict.items()}

        def get_value(key: str, worst: str):
            return cvss_dict.get(key, old_cvss_dict.get(key, worst))

        self.attackComplexity = AttackComplexity[get_value('attackComplexity', 'LOW')]
        self.attackVector = AttackVector[get_value('attackVector', 'NETWORK')]
        self.privilegesRequired = PrivilegesRequired[get_value('privilegesRequired', 'NONE')]
        self.userInteraction = UserInteraction[get_value('userInteraction', 'NONE')]
        self.availabilityImpact = AvailabilityImpact[get_value('availabilityImpact', 'HIGH')]
        self.confidentialityImpact = ConfidentialityImpact[get_value('confidentialityImpact', 'HIGH')]
        self.integrityImpact = IntegrityImpact[get_value('integrityImpact', 'HIGH')]
        self.scope = Scope[get_value('scope', 'CHANGED')]


    def vector(self):
        ac = get_enum_first_char(self.attackComplexity)
        av = get_enum_first_char(self.attackVector)
        pr = get_enum_first_char(self.privilegesRequired)
        ui = get_enum_first_char(self.userInteraction)
        s = get_enum_first_char(self.scope)
        ai = get_enum_first_char(self.availabilityImpact)
        ci = get_enum_first_char(self.confidentialityImpact)
        ii = get_enum_first_char(self.integrityImpact)

        return f'CVSS:3.0/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{s}/C:{ci}/I:{ii}/A:{ai}'

    def score(self):
        privileges_required = self.privilegesRequired.value[self.scope.value]

        impact_sub_score = 1 - ((1 - self.confidentialityImpact.value) *
                                (1 - self.integrityImpact.value) *
                                (1 - self.availabilityImpact.value))
        if self.scope == Scope.UNCHANGED:
            impact = 6.42 * impact_sub_score
        else:
            impact = 7.52 * (impact_sub_score - 0.029) - 3.25 * (impact_sub_score - 0.02) ** 15

        exploitability = 8.22 * self.attackVector.value * self.attackComplexity.value * privileges_required * self.userInteraction.value

        if impact <= 0:
            base = 0
        elif self.scope == Scope.UNCHANGED:
            base = math.ceil(min([100, (impact + exploitability) * 10])) / 10
        else:  # self.scope == Scope.CHANGED
            base = math.ceil(min([100, 1.08 * (impact + exploitability) * 10])) / 10

        return base

    def __str__(self):
        return self.vector()

    def __repr__(self):
        return f'{self.vector()} - [{self.score()}]'
