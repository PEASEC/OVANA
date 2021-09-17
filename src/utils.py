import json
import os
import zipfile
import hashlib
from itertools import chain, combinations

from nvd_entry import NVDEntry

DIRECTORY = 'nvd-files'


def get_cve_list(year: int):
    return get_dict(get_file(str(year)))['CVE_Items']


def get_cve_entry(cve_year_dict: dict, cve_id: str):
    _, _, num = cve_id.split('-')
    return cve_year_dict[int(num) - 1]


def filter_by_year(dataset: list[NVDEntry], year: int):
    return [e for e in dataset if e.year == year]


def filter_list_by_year(dataset: list, year: int):
    return [e for e in dataset if str(year) in e[0]]


def sha1hash(msg: str):
    return hashlib.sha1(msg.encode()).hexdigest()


def get_file(year: str):
    for file in os.listdir(DIRECTORY):
        if year in file:
            return file


def get_dict(file: str):
    archive = zipfile.ZipFile(os.path.join(DIRECTORY, file), 'r')
    with archive.open(archive.namelist()[0]) as f:
        return json.loads(f.read())


def powerset(iterable):
    s = list(iterable)
    return chain.from_iterable(combinations(s, r) for r in range(len(s) + 1))


def cpe_to_dict(cpe_23_uri: str):
    return ':'.join(cpe_23_uri.split(':'))

def parse_cvs_lists():
    directory = 'nvd-files/tagged_cves'
    classified_directory = 'nvd-files/tagged_and_classified'

    # Read files
    all_lines = {}
    for filename in os.listdir(classified_directory):
        lines = open(classified_directory + '/' + filename).readlines()
        all_lines[filename] = lines

    # Parse files
    for index_1, filename in enumerate(os.listdir(directory), start=1):
        new_lines = []
        lines = open(directory + '/' + filename, 'r').readlines()
        print(len(lines))
        for index, line in enumerate(lines, start=0):
            if not line.split():
                new_lines.append('')
                continue
            tag_string = ''
            tags = []
            for classified_filename in os.listdir(classified_directory):
                if str(index_1) in classified_filename:
                    classified_lines = all_lines[classified_filename]
                    if classified_lines[index].split()[1] != 'O':
                        tags.append(classified_lines[index].split()[1])
            if len(tags) == 0:
                tag_string = 'O'
            for tag_index, tag in enumerate(tags, start=1):
                if len(tags) == tag_index:
                    tag_string += (tag)
                else:
                    tag_string += (tag + ',')
            new_lines.append(line.split()[0] + ' ' + tag_string + ' ' + line.split()[1] + '\n')
        print(len(new_lines))

        # Write output file
        out_filename = 'nvd-files/all_cves_' + str(index_1) + '_all_tags.csv.xls'
        out_file = open(out_filename, 'w')
        for line in new_lines:
            if line == '':
                out_file.write('\n')
            else:
                out_file.write(line)
        out_file.close()
        print(len(open(out_filename, 'r').readlines()))

