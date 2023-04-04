# binary2name
Predicts common functions names in binary files, including ida plugin.

# Content:
## Server Side
Run prediction on input binary file. Contains all model (nero) files including training set binary files.
## Client Side
Contains ida plugin for binary file function names prediction (using the server for the prediction).
## Other
### ask chatGPT
asking chatGPT for prediction of functions from binary files
### function extractor
ida plugin used to extract function disasm code to ask chatGPT about
### scraper
github scraper, can be use for common functions scraping in github, to enlarge the training set of nero

