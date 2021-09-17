# OVANA

This repository hosts the code and datasets used in the paper _OVANA: An Approach to Analyze and Improve the Information Quality of Vulnerability Databases_ [1].

1: Kuehn, P., Bayer, M., Wendelborn, M., & Reuter, C. (2021). OVANA: An Approach to Analyze and Improve the Information Quality of Vulnerability Databases. Proceedings of the 16th International Conference on Availability, Reliability and Security, 11. https://doi.org/10.1145/3465481.3465744

## Quick Start

### Requirements

The project uses Python 3.8+. All requirements can be installed in your virtual environment using

```
pip install -r requirements.txt
```

The datasets are contained as zip files in the directory `dataset`. Simply unzip them in this directory to be found by the code in the different python notebooks.

### Preanalysis

The code for the preanalysis is given in `src/preanalysis.ipynb`. It produces all figures given in the paper's preanalysis section.

### CVSS Tagger

The code for the CVSS Tagger (`src/cvss_tagging.ipynb`) is written to work in Google Colab. According packages need to be installed in your Colab environment and the necessary dataset files need to be placed in the given directory in Google Drive (see `src/cvss_tagging.ipynb` for more information).

### Results

The code for the final analysis is given in `src/results.ipynb`. It produces all figures given in the paper's results section.


## Citing

If you make use of OVANA in any form, please cite the following Paper.

```
@inproceedings{kuehn2021ovana,
	title = {{OVANA}: {An} {Approach} to {Analyze} and {Improve} the {Information} {Quality} of {Vulnerability} {Databases}},
	isbn = {978-1-4503-9051-4},
	url = {https://doi.org/10.1145/3465481.3465744},
	doi = {10.1145/3465481.3465744},
	booktitle = {Proceedings of the 16th {International} {Conference} on {Availability}, {Reliability} and {Security}},
	publisher = {ACM},
	author = {Kuehn, Philipp and Bayer, Markus and Wendelborn, Marc and Reuter, Christian},
	year = {2021},
	pages = {11},
}
```

## Contributors

- Philipp Kühn
- Markus Bayer
- Marc Wendelborn


## License

Copyright (c) 2021 Philipp Kühn, Technical University Darmstadt

Permission to use, copy, modify, and distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

