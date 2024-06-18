
# NVD API Client

![PyPI](https://img.shields.io/pypi/v/nvd-client)
![Total Downloads](https://static.pepy.tech/personalized-badge/nvd-client?period=total&units=none&left_color=grey&right_color=blue&left_text=Total-PyPi-Downloads)
![Monthly Downloads](https://static.pepy.tech/personalized-badge/nvd-client?period=month&units=none&left_color=grey&right_color=blue&left_text=Monthly-PyPi-Downloads)
![Weekly Downloads](https://static.pepy.tech/personalized-badge/nvd-client?period=week&units=none&left_color=grey&right_color=blue&left_text=Weekly-PyPi-Downloads)
[![Telegram-Channel](https://img.shields.io/badge/Telegram--Channel-Ahura_Rahmani-blue)](https://t.me/Ahur4_Rahmani)


A Python client for interacting with the National Vulnerability Database (NVD) API to fetch CVE data.

## Features

- Fetch all CVEs with pagination
- Fetch CVE by its ID
- Fetch CVEs by publication or modification date
- Fetch CVEs by CPE name
- Other features coming soon...

## Installation

You can install the package using pip:

```sh
pip install nvd-client
```

## Usage

```python
from nvd_client import NvdApi

# Initialize the API client
api_key = "your_api_key_here"
nvd_api = NvdApi(api_key)

# Fetch all CVEs
cves = nvd_api.get_all_cves(per_page=100, offset=0)
print(cves)

# Fetch a CVE by ID
cve = nvd_api.get_cve_by_id(cve_id="CVE-2024-30078")
print(cve)

# Fetch CVEs by publish or modify date range
cves_by_date = nvd_api.get_cve_by_date(
    per_page=100,
    offset=0,
    publish_start_date="2021-01-01",
    publish_end_date="2021-12-31"
)
print(cves_by_date)

# Fetch CVEs by CPE name
cves_by_cpe = nvd_api.get_cve_by_cpe(
    cpe_name="cpe:2.3:o:microsoft:windows_10:1607:*:*:*:*:*:*:*",
    per_page=100,
    offset=0
)
print(cves_by_cpe)
```

## Author

- Author: Ahur4

- Telegram: [@Ahura_rahmani](https://t.me/Ahura_rahmani)

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.


### Explanation:
1. **Features**: Lists the main functionalities provided by the module.
2. **Installation**: Provides instructions for installing the package using pip from PyPI.
3. **Usage**: Gives examples of how to initialize the client and use its methods.
4. **Author**: Provides your name and a link to your Telegram channel.
5. **License**: States that the project is licensed under the MIT License.
