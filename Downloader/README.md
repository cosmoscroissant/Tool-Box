# Downloader
## Malware Sample Downloader
sample_downloader.py will log in to virus.exchange and download the malware samples that are shown on the web page. It will refresh every 15 seconds to check for new samples. Before running the script, please change these three values:
- `USERNAME = "your_username_here"`
- `PASSWORD = "your_password_here"`
- `DOWNLOAD_DIR = r"your_path_here"`

### How-To
`python3 sample_downloader.py`