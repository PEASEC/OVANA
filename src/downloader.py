import os
import re

import requests

from utils import DIRECTORY

URL = 'https://nvd.nist.gov/vuln/data-feeds#JSON_FEED'
FEED_ULR = 'https://nvd.nist.gov/feeds/json/cve/1.1'


class Downloader:
    def __init__(self):
        if not os.path.isdir(DIRECTORY):
            os.makedirs(DIRECTORY)
        self._request = requests.get(URL)

    def download(self, year: int):
        year_filename = [elem for elem in self._online_files() if str(year) in elem][0]

        if year_filename in self._downloaded_years():
            return

        file_stream = requests.get(f'{FEED_ULR}/{year_filename}', stream=True)
        with open(os.path.join(DIRECTORY, year_filename), 'wb') as f:
            for chunk in file_stream:
                f.write(chunk)

    def online_years(self):
        return sorted(re.findall('\d{4}', str(self._online_files())))

    def _online_files(self):
        return re.findall('nvdcve-1\.1-\d{4}\.json\.zip', self._request.text)

    @staticmethod
    def _downloaded_years():
        return os.listdir(DIRECTORY)
