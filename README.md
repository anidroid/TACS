## Text Analysis for Cyber Security (TACS)

TACS consists of an open-source dictionary `csd.csv`, or codebook, of ca. 700 words and phrases related to cyber security, organised into concepts (e.g., Hacking, Passwords, User) and grouped into overarching categories (e.g., Threat Mechanisms, Security Mechanisms, Cyber Entities), alongside a set of functions `tacs.py` to apply the dictionary codes to textual data and perform numeric transformations and queries.		

![TACS Framework](tacsfw.png)


## Installation

TACS consists of: Dictionary data file `csd.csv` and a python script `tacs.py` with functions to compile and use the dictionary from the Dictionary data.

Running TACS requires <a href="https://wiki.python.org/moin/BeginnersGuide/Download/" target="_blank">Python</a> and the libraries <a href="https://pandas.pydata.org/getting_started.html" target="_blank">pandas</a> and <a href="https://spacy.io/usage" target="_blank">spacy</a>. Interface and visualisations require <a href="https://jupyter.org/install" target="_blank">Jupyter Notebook</a>. With all required packages installed, download the files [tacs.py](tacs.py) and [csd.csv](csd.csv) and run tacs.py in a Python application.

The [Documentation](https://nbviewer.jupyter.org/github/anidroid/tacs/blob/master/Documentation-DRAFT.ipynb) can be accessed as an interactive Jupyter Notebook or HTML.

## Reference

More information about the project can be found in the following [preprint](https://nbviewer.jupyter.org/github/anidroid/tacs/blob/master/tacs-soups.pdf).

 
