from cvss import cvssv2, cvssv3


class NVDEntry:
    def __init__(self, cve_dict: dict):
        self.id: str = cve_dict['cve']['CVE_data_meta']['ID']
        self.year: int = int(self.id[4:8])

        problemtype_data = cve_dict['cve']['problemtype']['problemtype_data']
        self.cwe: set = set([cwe_entry['value'] for data in problemtype_data for cwe_entry in data['description']])

        self.cpe: list = cve_dict['configurations']['nodes']
        if 'baseMetricV2' in cve_dict['impact'].keys():
            self.cvssv2: cvssv2.CVSSV2 = cvssv2.CVSSV2(cve_dict['impact']['baseMetricV2']['cvssV2'])
        else:
            self.cvssv2 = None
        if 'baseMetricV3' in cve_dict['impact'].keys():
            self.cvssv3: cvssv3.CVSSV3 = cvssv3.CVSSV3(cve_dict['impact']['baseMetricV3']['cvssV3'])
        else:
            self.cvssv3 = None
        self.references: list = [e['url'] for e in cve_dict['cve']['references']['reference_data']]
        self.description: list = [e['value'] for e in cve_dict['cve']['description']['description_data']]
        self.rejected: bool = any('** REJECT **' in d for d in self.description)

        self.predicted_cvssv3: cvssv3 = None
        self.path: set = None
        self.vulnerable_function: set = None
        self.software_name: list = None
        self.software_version: list = None
        self.weakness: list = None

    def __cwe_classes(self):
        return

    def __eq__(self, other):
        if isinstance(other, NVDEntry):
            return self.cwe == other.cwe and \
                   self.cpe == other.cpe and \
                   self.cvssv2 == other.cvssv2 and \
                   self.cvssv3 == other.cvssv3

    def __hash__(self):
        return hash(self.id)

    def __repr__(self):
        return str(self.__dict__)

    def __str__(self):
        return self.__repr__()
