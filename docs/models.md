# Data models

Every successful call returns a pydantic v2 model. Attributes are snake_case. The NVD names are aliases, so both forms validate (`populate_by_name=True`). The base class is `NvdModel`.

Unknown JSON keys are kept (`extra="allow"`). They show up in `model_dump()` under the key NVD sent, which is not rewritten to snake_case. A field NVD adds later does not drop the rest of the document.

Dates are `datetime` values. NVD often omits the offset; those values stay naive. Strings that include `Z` or a numeric offset are aware. `cisa_exploit_add` and `cisa_action_due` are `datetime.date`, not `datetime`.

The generated field list, including every optional CVSS metric, is [`nvd_client.models`](reference/models.md). This page is the map of that module.

## Serialization

```python
record.model_dump()
record.model_dump(by_alias=True)
record.model_dump(by_alias=True, mode="json", exclude_none=True)
record.model_dump_json(by_alias=True, indent=2)
```

| Call | Keys | `datetime` values |
| --- | --- | --- |
| `model_dump()` | Python names (`last_modified`) | `datetime` objects |
| `model_dump(by_alias=True)` | NVD names (`lastModified`) | `datetime` objects |
| `model_dump(by_alias=True, mode="json")` | NVD names | ISO strings |
| `model_dump_json(by_alias=True)` | NVD names | ISO strings inside a JSON string |

`exclude_none=True` is a normal pydantic option. The client does not pass it for you. Metric groups that NVD omits are empty lists, not `None`, so they are still present when `exclude_none` is set.

Both spellings validate:

```python
from nvd_client.models import CveRecord

CveRecord.model_validate(
    {
        "id": "CVE-2020-0001",
        "published": "2020-01-01T00:00:00.000",
        "lastModified": "2020-01-02T00:00:00.000",
        "descriptions": [{"lang": "en", "value": "Minimal."}],
        "references": [{"url": "https://example.com/cve"}],
    }
)
```

`last_modified=` is accepted as well, because `populate_by_name` is on.

An unknown key is preserved on both dumps:

```python
document = record.model_dump()
document["futureField"]  # the original key, kept
record.model_dump(by_alias=True)["futureField"]
```

## `CveListResponse`

A page from `/cves/2.0`. `total_results` is the size of the full match, not this page. An empty page is success: `total_results == 0` and `cves == []`.

| Attribute | NVD name | Meaning |
| --- | --- | --- |
| `results_per_page` | `resultsPerPage` | Records in this response |
| `start_index` | `startIndex` | Offset NVD used |
| `total_results` | `totalResults` | Size of the full match |
| `format` | `format` | Response format name, such as `NVD_CVE` |
| `version` | `version` | API version string |
| `timestamp` | `timestamp` | When NVD generated the page |
| `vulnerabilities` | `vulnerabilities` | `CveItem` wrappers |
| `cves` | | `CveRecord` objects on this page, in NVD's order |

`cves` is a property. It is not a JSON key. `CveItem` has one field, `cve`, which is the `CveRecord`.

## `CveRecord`

One CVE, the `cve` object inside a vulnerability. Required by the schema: `id`, `published`, `lastModified`, `descriptions`, and `references`. Every other attribute defaults to empty or `None` when NVD omits it.

`description(lang="en")` returns that language's text, compared case-insensitively, or `None`. `cwe_ids` is the weakness description values with surrounding whitespace removed. Empty strings are skipped. The order follows `weaknesses`.

| Attribute | NVD name | Notes |
| --- | --- | --- |
| `id` | `id` | `CVE-YYYY-NNNN` |
| `source_identifier` | `sourceIdentifier` | Optional |
| `vuln_status` | `vulnStatus` | Optional |
| `published` | `published` | `datetime`, required |
| `last_modified` | `lastModified` | `datetime`, required |
| `descriptions` | `descriptions` | `LangString` (`lang`, `value`), required |
| `references` | `references` | `Reference`, required |
| `metrics` | `metrics` | `Metrics`. Defaults to empty metric lists |
| `weaknesses` | `weaknesses` | `Weakness` |
| `configurations` | `configurations` | CPE applicability trees |
| `affected` | `affected` | `Affected` |
| `cve_tags` | `cveTags` | `CveTag` |
| `vendor_comments` | `vendorComments` | `VendorComment` |
| `evaluator_comment` | `evaluatorComment` | Optional |
| `evaluator_solution` | `evaluatorSolution` | Optional |
| `evaluator_impact` | `evaluatorImpact` | Optional |
| `cisa_exploit_add` | `cisaExploitAdd` | `date`, when the CVE is in the KEV catalog |
| `cisa_action_due` | `cisaActionDue` | `date` |
| `cisa_required_action` | `cisaRequiredAction` | Optional |
| `cisa_vulnerability_name` | `cisaVulnerabilityName` | Optional |

## Descriptions, references, tags, comments

### `LangString`

Used by descriptions and by weakness descriptions.

| Attribute | NVD name | Required |
| --- | --- | --- |
| `lang` | `lang` | yes |
| `value` | `value` | yes |

### `Reference`

| Attribute | NVD name | Required |
| --- | --- | --- |
| `url` | `url` | yes |
| `source` | `source` | no |
| `tags` | `tags` | no, defaults to `[]` |

### `CveTag`

A source-scoped tag such as `disputed`.

| Attribute | NVD name | Required |
| --- | --- | --- |
| `source_identifier` | `sourceIdentifier` | no |
| `tags` | `tags` | no, defaults to `[]` |

### `VendorComment`

| Attribute | NVD name | Required |
| --- | --- | --- |
| `organization` | `organization` | yes |
| `comment` | `comment` | yes |
| `last_modified` | `lastModified` | yes, `datetime` |

### `Weakness`

`description` values are identifiers such as `CWE-79` or `NVD-CWE-noinfo`.

| Attribute | NVD name | Required |
| --- | --- | --- |
| `source` | `source` | yes |
| `type` | `type` | yes |
| `description` | `description` | no, defaults to `[]` of `LangString` |

## Configurations

A `Configuration` is an AND/OR tree of CPE match nodes.

| Model | Attribute | NVD name | Required |
| --- | --- | --- | --- |
| `Configuration` | `nodes` | `nodes` | yes, `ConfigNode` |
| `Configuration` | `operator` | `operator` | no |
| `Configuration` | `negate` | `negate` | no |
| `ConfigNode` | `operator` | `operator` | yes |
| `ConfigNode` | `negate` | `negate` | no |
| `ConfigNode` | `cpe_match` | `cpeMatch` | yes, `CpeMatch` |
| `CpeMatch` | `vulnerable` | `vulnerable` | yes |
| `CpeMatch` | `criteria` | `criteria` | yes |
| `CpeMatch` | `match_criteria_id` | `matchCriteriaId` | yes |
| `CpeMatch` | `version_start_excluding` | `versionStartExcluding` | no |
| `CpeMatch` | `version_start_including` | `versionStartIncluding` | no |
| `CpeMatch` | `version_end_excluding` | `versionEndExcluding` | no |
| `CpeMatch` | `version_end_including` | `versionEndIncluding` | no |

`CpeMatch` here is the criterion inside a CVE configuration. It is not `CpeMatchString` from the CPE Match API.

## Metrics

`Metrics` holds five lists. A group NVD omits is `[]`, not `None`.

| Attribute | NVD name | Item |
| --- | --- | --- |
| `cvss_metric_v40` | `cvssMetricV40` | `CvssMetricV40` |
| `cvss_metric_v31` | `cvssMetricV31` | `CvssMetricV31` |
| `cvss_metric_v30` | `cvssMetricV30` | `CvssMetricV30` |
| `cvss_metric_v2` | `cvssMetricV2` | `CvssMetricV2` |
| `ssvc_v203` | `ssvcV203` | `SsvcMetric` |

Each CVSS metric has `source`, `type` (`Primary` or `Secondary` when NVD sends those words), and `cvss_data`. v2, v3.0, and v3.1 wrappers also carry `exploitability_score` (`exploitabilityScore`) and `impact_score` (`impactScore`) when NVD sends them. v2 adds the fields below. v4 threat and environmental scores live on `cvss_data`, not on the wrapper.

### `CvssMetricV2` and `CvssV2Data`

`CvssV2Data.version` is the literal `"2.0"`.

| Attribute | NVD name |
| --- | --- |
| `source` | `source` |
| `type` | `type` |
| `cvss_data` | `cvssData` |
| `base_severity` | `baseSeverity` |
| `exploitability_score` | `exploitabilityScore` |
| `impact_score` | `impactScore` |
| `ac_insuf_info` | `acInsufInfo` |
| `obtain_all_privilege` | `obtainAllPrivilege` |
| `obtain_user_privilege` | `obtainUserPrivilege` |
| `obtain_other_privilege` | `obtainOtherPrivilege` |
| `user_interaction_required` | `userInteractionRequired` |

`CvssV2Data` fields other than `version`:

| Attribute | NVD name |
| --- | --- |
| `vector_string` | `vectorString` |
| `base_score` | `baseScore` |
| `access_vector` | `accessVector` |
| `access_complexity` | `accessComplexity` |
| `authentication` | `authentication` |
| `confidentiality_impact` | `confidentialityImpact` |
| `integrity_impact` | `integrityImpact` |
| `availability_impact` | `availabilityImpact` |
| `exploitability` | `exploitability` |
| `remediation_level` | `remediationLevel` |
| `report_confidence` | `reportConfidence` |
| `temporal_score` | `temporalScore` |
| `collateral_damage_potential` | `collateralDamagePotential` |
| `target_distribution` | `targetDistribution` |
| `confidentiality_requirement` | `confidentialityRequirement` |
| `integrity_requirement` | `integrityRequirement` |
| `availability_requirement` | `availabilityRequirement` |
| `environmental_score` | `environmentalScore` |

`version`, `vector_string`, and `base_score` are required. The rest are optional.

### CVSS v3.0 and v3.1

`CvssMetricV30` / `CvssMetricV31` each have `source`, `type`, `cvss_data`, and optional `exploitability_score` and `impact_score`.

`CvssV30Data.version` is `"3.0"`. `CvssV31Data.version` is `"3.1"`. Both data objects have the same other fields. `version`, `vector_string`, `base_score`, and `base_severity` are required.

| Attribute | NVD name |
| --- | --- |
| `vector_string` | `vectorString` |
| `base_score` | `baseScore` |
| `base_severity` | `baseSeverity` |
| `attack_vector` | `attackVector` |
| `attack_complexity` | `attackComplexity` |
| `privileges_required` | `privilegesRequired` |
| `user_interaction` | `userInteraction` |
| `scope` | `scope` |
| `confidentiality_impact` | `confidentialityImpact` |
| `integrity_impact` | `integrityImpact` |
| `availability_impact` | `availabilityImpact` |
| `exploit_code_maturity` | `exploitCodeMaturity` |
| `remediation_level` | `remediationLevel` |
| `report_confidence` | `reportConfidence` |
| `temporal_score` | `temporalScore` |
| `temporal_severity` | `temporalSeverity` |
| `confidentiality_requirement` | `confidentialityRequirement` |
| `integrity_requirement` | `integrityRequirement` |
| `availability_requirement` | `availabilityRequirement` |
| `modified_attack_vector` | `modifiedAttackVector` |
| `modified_attack_complexity` | `modifiedAttackComplexity` |
| `modified_privileges_required` | `modifiedPrivilegesRequired` |
| `modified_user_interaction` | `modifiedUserInteraction` |
| `modified_scope` | `modifiedScope` |
| `modified_confidentiality_impact` | `modifiedConfidentialityImpact` |
| `modified_integrity_impact` | `modifiedIntegrityImpact` |
| `modified_availability_impact` | `modifiedAvailabilityImpact` |
| `environmental_score` | `environmentalScore` |
| `environmental_severity` | `environmentalSeverity` |

### CVSS v4.0

`CvssMetricV40` has `source`, `type`, and `cvss_data` (`cvssData`). It does not have `exploitability_score` or `impact_score`.

`CvssV40Data.version` is `"4.0"`. `version`, `vector_string`, `base_score`, and `base_severity` are required. Threat and environmental scores are on this object.

Three supplemental aliases are PascalCase, matching the NVD schema: `safety` is `Safety`, `automatable` is `Automatable`, and `recovery` is `Recovery`.

| Attribute | NVD name |
| --- | --- |
| `vector_string` | `vectorString` |
| `base_score` | `baseScore` |
| `base_severity` | `baseSeverity` |
| `attack_vector` | `attackVector` |
| `attack_complexity` | `attackComplexity` |
| `attack_requirements` | `attackRequirements` |
| `privileges_required` | `privilegesRequired` |
| `user_interaction` | `userInteraction` |
| `vuln_confidentiality_impact` | `vulnConfidentialityImpact` |
| `vuln_integrity_impact` | `vulnIntegrityImpact` |
| `vuln_availability_impact` | `vulnAvailabilityImpact` |
| `sub_confidentiality_impact` | `subConfidentialityImpact` |
| `sub_integrity_impact` | `subIntegrityImpact` |
| `sub_availability_impact` | `subAvailabilityImpact` |
| `exploit_maturity` | `exploitMaturity` |
| `confidentiality_requirement` | `confidentialityRequirement` |
| `integrity_requirement` | `integrityRequirement` |
| `availability_requirement` | `availabilityRequirement` |
| `modified_attack_vector` | `modifiedAttackVector` |
| `modified_attack_complexity` | `modifiedAttackComplexity` |
| `modified_attack_requirements` | `modifiedAttackRequirements` |
| `modified_privileges_required` | `modifiedPrivilegesRequired` |
| `modified_user_interaction` | `modifiedUserInteraction` |
| `modified_vuln_confidentiality_impact` | `modifiedVulnConfidentialityImpact` |
| `modified_vuln_integrity_impact` | `modifiedVulnIntegrityImpact` |
| `modified_vuln_availability_impact` | `modifiedVulnAvailabilityImpact` |
| `modified_sub_confidentiality_impact` | `modifiedSubConfidentialityImpact` |
| `modified_sub_integrity_impact` | `modifiedSubIntegrityImpact` |
| `modified_sub_availability_impact` | `modifiedSubAvailabilityImpact` |
| `safety` | `Safety` |
| `automatable` | `Automatable` |
| `recovery` | `Recovery` |
| `value_density` | `valueDensity` |
| `vulnerability_response_effort` | `vulnerabilityResponseEffort` |
| `provider_urgency` | `providerUrgency` |
| `threat_score` | `threatScore` |
| `threat_severity` | `threatSeverity` |
| `environmental_score` | `environmentalScore` |
| `environmental_severity` | `environmentalSeverity` |

### SSVC

`SsvcMetric` is one Stakeholder-Specific Vulnerability Categorization assessment (v2.0.3).

| Model | Attribute | NVD name | Required |
| --- | --- | --- | --- |
| `SsvcMetric` | `source` | `source` | yes |
| `SsvcMetric` | `ssvc_data` | `ssvcData` | yes |
| `SsvcData` | `options` | `options` | yes, a list of dicts (`str` or `list[str]` values) |
| `SsvcData` | `role` | `role` | yes |
| `SsvcData` | `version` | `version` | yes |
| `SsvcData` | `computed` | `computed` | no |
| `SsvcData` | `timestamp` | `timestamp` | no, `datetime` |
| `SsvcData` | `id` | `id` | no |
| `SsvcData` | `decision_tree_url` | `decisionTreeUrl` | no |
| `SsvcData` | `generator` | `generator` | no |

## Affected products

| Model | Attribute | NVD name | Required |
| --- | --- | --- | --- |
| `Affected` | `source` | `source` | yes |
| `Affected` | `affected_data` | `affectedData` | yes, `AffectedProduct` |
| `AffectedProduct` | `vendor` | `vendor` | no |
| `AffectedProduct` | `product` | `product` | no |
| `AffectedProduct` | `collection_url` | `collectionURL` | no |
| `AffectedProduct` | `package_name` | `packageName` | no |
| `AffectedProduct` | `cpes` | `cpes` | no, defaults to `[]` |
| `AffectedProduct` | `modules` | `modules` | no, defaults to `[]` |
| `AffectedProduct` | `program_files` | `programFiles` | no, defaults to `[]` |
| `AffectedProduct` | `program_routines` | `programRoutines` | no, defaults to `[]` of `ProgramRoutine` |
| `AffectedProduct` | `platforms` | `platforms` | no, defaults to `[]` |
| `AffectedProduct` | `repo` | `repo` | no |
| `AffectedProduct` | `default_status` | `defaultStatus` | no |
| `AffectedProduct` | `versions` | `versions` | no, defaults to `[]` of `AffectedVersion` |
| `AffectedProduct` | `package_url` | `packageURL` | no |
| `ProgramRoutine` | `name` | `name` | yes |
| `AffectedVersion` | `version` | `version` | yes |
| `AffectedVersion` | `status` | `status` | yes |
| `AffectedVersion` | `version_type` | `versionType` | no |
| `AffectedVersion` | `less_than` | `lessThan` | no |
| `AffectedVersion` | `less_than_or_equal` | `lessThanOrEqual` | no |
| `AffectedVersion` | `changes` | `changes` | no, defaults to `[]` of `VersionChange` |
| `VersionChange` | `at` | `at` | yes |
| `VersionChange` | `status` | `status` | yes |

## `CpeMatchResponse`

A page from `/cpematch/2.0`.

| Attribute | NVD name | Meaning |
| --- | --- | --- |
| `results_per_page` | `resultsPerPage` | Match strings in this response |
| `start_index` | `startIndex` | Offset NVD used |
| `total_results` | `totalResults` | Size of the full match |
| `format` | `format` | Response format name |
| `version` | `version` | API version string |
| `timestamp` | `timestamp` | When NVD generated the page |
| `match_strings` | `matchStrings` | `CpeMatchStringItem` wrappers |
| `matches` | | The `CpeMatchString` objects on this page |

`matches` is a property. It is not a JSON key. `CpeMatchStringItem` has one field, `match_string` (`matchString`).

### `CpeMatchString`

| Attribute | NVD name | Required |
| --- | --- | --- |
| `criteria` | `criteria` | yes |
| `match_criteria_id` | `matchCriteriaId` | yes |
| `created` | `created` | yes, `datetime` |
| `last_modified` | `lastModified` | yes, `datetime` |
| `status` | `status` | yes |
| `version_start_excluding` | `versionStartExcluding` | no |
| `version_start_including` | `versionStartIncluding` | no |
| `version_end_excluding` | `versionEndExcluding` | no |
| `version_end_including` | `versionEndIncluding` | no |
| `cpe_last_modified` | `cpeLastModified` | no, `datetime` |
| `matches` | `matches` | no, defaults to `[]` of `CpeNameMatch` |

`CpeNameMatch` is a dictionary CPE name that satisfies the match string.

| Attribute | NVD name | Required |
| --- | --- | --- |
| `cpe_name` | `cpeName` | yes |
| `cpe_name_id` | `cpeNameId` | yes |

`model_dump_json(by_alias=True)` on a page uses `matchStrings` and, inside each item, `matchString`.
