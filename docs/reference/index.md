# API reference

These pages are generated from the docstrings and type hints. The names
below are what `import nvd_client` exports (`nvd_client.__all__`).

| Name | Module |
| --- | --- |
| `NvdApi` | [`nvd_client.api`](api.md) |
| `NvdConfig` | [`nvd_client.config`](config.md) |
| `CveListResponse`, `CveRecord`, `CpeMatchResponse` | [`nvd_client.models`](models.md) |
| `NvdClientError`, `InvalidDateFormatError`, `InvalidParametersError`, `InvalidCVEIDError`, `NvdApiError`, `NvdRateLimitError`, `NvdNotFoundError`, `NvdResponseError` | [`nvd_client.exceptions`](exceptions.md) |
| `__version__` | `nvd_client.version` |

```python
import nvd_client
from nvd_client import NvdApi, NvdConfig

nvd_client.__version__
```

[`nvd_client.utils`](utils.md) formats timestamps and checks CVE ids. It
is importable, and it is not part of `__all__`. `nvd_client.version`
only holds `__version__`, which stays in sync with `[project].version`
in `pyproject.toml`.

Narrative guides:

- [Quickstart](../quickstart.md)
- [Configuration](../configuration.md)
- [Data models](../models.md)
- [Error handling](../errors.md)
- [Retries and rate limiting](../retries.md)
