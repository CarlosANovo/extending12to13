# Extending 1.2 to 1.3

This repository contains the code of the implementation and experiments associated with the paper *"Extending C2 Traffic Detection Methodologies: From TLS 1.2 to TLS 1.3-enabled Malware"*.

If you find these any useful, please cite the original work.

## Instructions
The code is provided as a set of *Jupyter Notebooks*, to be run in order.  
 Then there is a notebook for each different classifier.

Notebooks starting with `01` are data-related. They parse files from `data/`, and output CSVs into `processed-datasets/`.  
If you wish to run them, make sure you download/unzip all necessary files into their corresponding `data/...` folders.

**Otherwise, you can go straight to the classifiers (`02`, `03` and `04`).**  
The required CSVs are provided in the `preprocessed-datasets/` directory for convenience (which you must unzip).

The experiments were run using **Python 3.10** and the packages listed in [`requirements.txt`](requirements.txt).

## Datasets
The "in-house" datasets can be obtained in the following URLs:
 * **MS dataset:** https://osf.io/b64e5/
 * **Tranco Web TLS 1.2 & TLS 1.3 dataset:** https://osf.io/zq9vs/

You can find further details on each one on their corresponding pages.  
Feel free to use these datasets for other experiments. If you do, you must include a citation of our work.
___

The **[MTA](https://malware-traffic-analysis.net)** and **[DoHBrw](https://www.unb.ca/cic/datasets/dohbrw-2020.html)** datasets are public. They were scraped, preprocessed and filtered.  
We include CSV files resulting from our preprocessing, for the convenience of those attempting to reproduce our results.

Keep in mind that **these files are not the full datasets**, and **we are not their original authors**!

If you wish to use the MTA or DoHBrw datasets in your research, please use their original sources, and cite their authors.
 - **MTA:** https://malware-traffic-analysis.net
 - **DoHBrw:** https://www.unb.ca/cic/datasets/dohbrw-2020.html

