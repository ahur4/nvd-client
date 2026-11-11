"""Pydantic models for NVD API 2.0 documents.

The field set follows the NVD Vulnerability Data API schema (2.2.4) and the
CPE Match Criteria API schema, including the CVSS v2.0, v3.0, v3.1, and v4.0
objects those documents reference.

Unknown keys are kept (``extra="allow"``) so a later NVD field still shows up
in :meth:`~pydantic.BaseModel.model_dump` instead of being dropped. Declared
fields use snake_case in Python and the API's camelCase as an alias.
``model_dump()`` emits snake_case; ``model_dump(by_alias=True)`` emits the
NVD names. ``model_dump_json()`` accepts the same arguments.

Dates are :class:`datetime.datetime` values. NVD often omits the offset;
those values stay naive. Strings that include ``Z`` or an offset are aware.
"""

from datetime import date, datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class NvdModel(BaseModel):
    """Base model for every NVD document in this package."""

    model_config = ConfigDict(populate_by_name=True, extra="allow")


class LangString(NvdModel):
    """A language-tagged string used by descriptions and weaknesses."""

    lang: str
    value: str


class Reference(NvdModel):
    """A supplemental URL attached to a CVE."""

    url: str
    source: str | None = None
    tags: list[str] = Field(default_factory=list)


class CveTag(NvdModel):
    """A source-scoped tag such as ``disputed``."""

    source_identifier: str | None = Field(default=None, alias="sourceIdentifier")
    tags: list[str] = Field(default_factory=list)


class VendorComment(NvdModel):
    """An official vendor comment submitted to NVD."""

    organization: str
    comment: str
    last_modified: datetime = Field(alias="lastModified")


class CpeMatch(NvdModel):
    """One CPE match criterion inside a CVE configuration node."""

    vulnerable: bool
    criteria: str
    match_criteria_id: str = Field(alias="matchCriteriaId")
    version_start_excluding: str | None = Field(default=None, alias="versionStartExcluding")
    version_start_including: str | None = Field(default=None, alias="versionStartIncluding")
    version_end_excluding: str | None = Field(default=None, alias="versionEndExcluding")
    version_end_including: str | None = Field(default=None, alias="versionEndIncluding")


class ConfigNode(NvdModel):
    """A node in a CVE applicability statement."""

    operator: str
    cpe_match: list[CpeMatch] = Field(alias="cpeMatch")
    negate: bool | None = None


class Configuration(NvdModel):
    """A CVE configuration (an AND/OR tree of CPE match nodes)."""

    nodes: list[ConfigNode]
    operator: str | None = None
    negate: bool | None = None


class Weakness(NvdModel):
    """A CWE (or NVD placeholder) associated with a CVE.

    ``description`` values are identifiers such as ``CWE-79`` or
    ``NVD-CWE-noinfo``.
    """

    source: str
    type: str
    description: list[LangString] = Field(default_factory=list)


class CvssV2Data(NvdModel):
    """CVSS v2.0 ``cvssData`` object."""

    version: Literal["2.0"]
    vector_string: str = Field(alias="vectorString")
    base_score: float = Field(alias="baseScore")
    access_vector: str | None = Field(default=None, alias="accessVector")
    access_complexity: str | None = Field(default=None, alias="accessComplexity")
    authentication: str | None = None
    confidentiality_impact: str | None = Field(default=None, alias="confidentialityImpact")
    integrity_impact: str | None = Field(default=None, alias="integrityImpact")
    availability_impact: str | None = Field(default=None, alias="availabilityImpact")
    exploitability: str | None = None
    remediation_level: str | None = Field(default=None, alias="remediationLevel")
    report_confidence: str | None = Field(default=None, alias="reportConfidence")
    temporal_score: float | None = Field(default=None, alias="temporalScore")
    collateral_damage_potential: str | None = Field(default=None, alias="collateralDamagePotential")
    target_distribution: str | None = Field(default=None, alias="targetDistribution")
    confidentiality_requirement: str | None = Field(
        default=None, alias="confidentialityRequirement"
    )
    integrity_requirement: str | None = Field(default=None, alias="integrityRequirement")
    availability_requirement: str | None = Field(default=None, alias="availabilityRequirement")
    environmental_score: float | None = Field(default=None, alias="environmentalScore")


class CvssMetricV2(NvdModel):
    """One CVSS v2 score, including NVD's wrapper fields."""

    source: str
    type: str
    cvss_data: CvssV2Data = Field(alias="cvssData")
    base_severity: str | None = Field(default=None, alias="baseSeverity")
    exploitability_score: float | None = Field(default=None, alias="exploitabilityScore")
    impact_score: float | None = Field(default=None, alias="impactScore")
    ac_insuf_info: bool | None = Field(default=None, alias="acInsufInfo")
    obtain_all_privilege: bool | None = Field(default=None, alias="obtainAllPrivilege")
    obtain_user_privilege: bool | None = Field(default=None, alias="obtainUserPrivilege")
    obtain_other_privilege: bool | None = Field(default=None, alias="obtainOtherPrivilege")
    user_interaction_required: bool | None = Field(default=None, alias="userInteractionRequired")


class _CvssV3Data(NvdModel):
    """Shared CVSS v3.0 / v3.1 ``cvssData`` fields."""

    version: str
    vector_string: str = Field(alias="vectorString")
    base_score: float = Field(alias="baseScore")
    base_severity: str = Field(alias="baseSeverity")
    attack_vector: str | None = Field(default=None, alias="attackVector")
    attack_complexity: str | None = Field(default=None, alias="attackComplexity")
    privileges_required: str | None = Field(default=None, alias="privilegesRequired")
    user_interaction: str | None = Field(default=None, alias="userInteraction")
    scope: str | None = None
    confidentiality_impact: str | None = Field(default=None, alias="confidentialityImpact")
    integrity_impact: str | None = Field(default=None, alias="integrityImpact")
    availability_impact: str | None = Field(default=None, alias="availabilityImpact")
    exploit_code_maturity: str | None = Field(default=None, alias="exploitCodeMaturity")
    remediation_level: str | None = Field(default=None, alias="remediationLevel")
    report_confidence: str | None = Field(default=None, alias="reportConfidence")
    temporal_score: float | None = Field(default=None, alias="temporalScore")
    temporal_severity: str | None = Field(default=None, alias="temporalSeverity")
    confidentiality_requirement: str | None = Field(
        default=None, alias="confidentialityRequirement"
    )
    integrity_requirement: str | None = Field(default=None, alias="integrityRequirement")
    availability_requirement: str | None = Field(default=None, alias="availabilityRequirement")
    modified_attack_vector: str | None = Field(default=None, alias="modifiedAttackVector")
    modified_attack_complexity: str | None = Field(default=None, alias="modifiedAttackComplexity")
    modified_privileges_required: str | None = Field(
        default=None, alias="modifiedPrivilegesRequired"
    )
    modified_user_interaction: str | None = Field(default=None, alias="modifiedUserInteraction")
    modified_scope: str | None = Field(default=None, alias="modifiedScope")
    modified_confidentiality_impact: str | None = Field(
        default=None, alias="modifiedConfidentialityImpact"
    )
    modified_integrity_impact: str | None = Field(default=None, alias="modifiedIntegrityImpact")
    modified_availability_impact: str | None = Field(
        default=None, alias="modifiedAvailabilityImpact"
    )
    environmental_score: float | None = Field(default=None, alias="environmentalScore")
    environmental_severity: str | None = Field(default=None, alias="environmentalSeverity")


class CvssV30Data(_CvssV3Data):
    """CVSS v3.0 ``cvssData`` object."""

    version: Literal["3.0"]


class CvssV31Data(_CvssV3Data):
    """CVSS v3.1 ``cvssData`` object."""

    version: Literal["3.1"]


class _CvssV3Metric(NvdModel):
    """Shared CVSS v3 metric wrapper."""

    source: str
    type: str
    exploitability_score: float | None = Field(default=None, alias="exploitabilityScore")
    impact_score: float | None = Field(default=None, alias="impactScore")


class CvssMetricV30(_CvssV3Metric):
    """One CVSS v3.0 score."""

    cvss_data: CvssV30Data = Field(alias="cvssData")


class CvssMetricV31(_CvssV3Metric):
    """One CVSS v3.1 score."""

    cvss_data: CvssV31Data = Field(alias="cvssData")


class CvssV40Data(NvdModel):
    """CVSS v4.0 ``cvssData`` object."""

    version: Literal["4.0"]
    vector_string: str = Field(alias="vectorString")
    base_score: float = Field(alias="baseScore")
    base_severity: str = Field(alias="baseSeverity")
    attack_vector: str | None = Field(default=None, alias="attackVector")
    attack_complexity: str | None = Field(default=None, alias="attackComplexity")
    attack_requirements: str | None = Field(default=None, alias="attackRequirements")
    privileges_required: str | None = Field(default=None, alias="privilegesRequired")
    user_interaction: str | None = Field(default=None, alias="userInteraction")
    vuln_confidentiality_impact: str | None = Field(default=None, alias="vulnConfidentialityImpact")
    vuln_integrity_impact: str | None = Field(default=None, alias="vulnIntegrityImpact")
    vuln_availability_impact: str | None = Field(default=None, alias="vulnAvailabilityImpact")
    sub_confidentiality_impact: str | None = Field(default=None, alias="subConfidentialityImpact")
    sub_integrity_impact: str | None = Field(default=None, alias="subIntegrityImpact")
    sub_availability_impact: str | None = Field(default=None, alias="subAvailabilityImpact")
    exploit_maturity: str | None = Field(default=None, alias="exploitMaturity")
    confidentiality_requirement: str | None = Field(
        default=None, alias="confidentialityRequirement"
    )
    integrity_requirement: str | None = Field(default=None, alias="integrityRequirement")
    availability_requirement: str | None = Field(default=None, alias="availabilityRequirement")
    modified_attack_vector: str | None = Field(default=None, alias="modifiedAttackVector")
    modified_attack_complexity: str | None = Field(default=None, alias="modifiedAttackComplexity")
    modified_attack_requirements: str | None = Field(
        default=None, alias="modifiedAttackRequirements"
    )
    modified_privileges_required: str | None = Field(
        default=None, alias="modifiedPrivilegesRequired"
    )
    modified_user_interaction: str | None = Field(default=None, alias="modifiedUserInteraction")
    modified_vuln_confidentiality_impact: str | None = Field(
        default=None, alias="modifiedVulnConfidentialityImpact"
    )
    modified_vuln_integrity_impact: str | None = Field(
        default=None, alias="modifiedVulnIntegrityImpact"
    )
    modified_vuln_availability_impact: str | None = Field(
        default=None, alias="modifiedVulnAvailabilityImpact"
    )
    modified_sub_confidentiality_impact: str | None = Field(
        default=None, alias="modifiedSubConfidentialityImpact"
    )
    modified_sub_integrity_impact: str | None = Field(
        default=None, alias="modifiedSubIntegrityImpact"
    )
    modified_sub_availability_impact: str | None = Field(
        default=None, alias="modifiedSubAvailabilityImpact"
    )
    safety: str | None = Field(default=None, alias="Safety")
    automatable: str | None = Field(default=None, alias="Automatable")
    recovery: str | None = Field(default=None, alias="Recovery")
    value_density: str | None = Field(default=None, alias="valueDensity")
    vulnerability_response_effort: str | None = Field(
        default=None, alias="vulnerabilityResponseEffort"
    )
    provider_urgency: str | None = Field(default=None, alias="providerUrgency")
    threat_score: float | None = Field(default=None, alias="threatScore")
    threat_severity: str | None = Field(default=None, alias="threatSeverity")
    environmental_score: float | None = Field(default=None, alias="environmentalScore")
    environmental_severity: str | None = Field(default=None, alias="environmentalSeverity")


class CvssMetricV40(NvdModel):
    """One CVSS v4.0 score."""

    source: str
    type: str
    cvss_data: CvssV40Data = Field(alias="cvssData")


class SsvcData(NvdModel):
    """Stakeholder-Specific Vulnerability Categorization decision (v2.0.3)."""

    options: list[dict[str, str | list[str]]]
    role: str
    version: str
    computed: str | None = None
    timestamp: datetime | None = None
    id: str | None = None
    decision_tree_url: str | None = Field(default=None, alias="decisionTreeUrl")
    generator: str | None = None


class SsvcMetric(NvdModel):
    """One SSVC assessment attached to a CVE."""

    source: str
    ssvc_data: SsvcData = Field(alias="ssvcData")


class VersionChange(NvdModel):
    """A status change inside an affected-version range."""

    at: str
    status: str


class AffectedVersion(NvdModel):
    """One version or version range of an affected product."""

    version: str
    status: str
    version_type: str | None = Field(default=None, alias="versionType")
    less_than: str | None = Field(default=None, alias="lessThan")
    less_than_or_equal: str | None = Field(default=None, alias="lessThanOrEqual")
    changes: list[VersionChange] = Field(default_factory=list)


class ProgramRoutine(NvdModel):
    """A named function or method listed as affected."""

    name: str


class AffectedProduct(NvdModel):
    """Product data inside an ``affected`` entry."""

    vendor: str | None = None
    product: str | None = None
    collection_url: str | None = Field(default=None, alias="collectionURL")
    package_name: str | None = Field(default=None, alias="packageName")
    cpes: list[str] = Field(default_factory=list)
    modules: list[str] = Field(default_factory=list)
    program_files: list[str] = Field(default_factory=list, alias="programFiles")
    program_routines: list[ProgramRoutine] = Field(default_factory=list, alias="programRoutines")
    platforms: list[str] = Field(default_factory=list)
    repo: str | None = None
    default_status: str | None = Field(default=None, alias="defaultStatus")
    versions: list[AffectedVersion] = Field(default_factory=list)
    package_url: str | None = Field(default=None, alias="packageURL")


class Affected(NvdModel):
    """A source's list of products affected by a CVE."""

    source: str
    affected_data: list[AffectedProduct] = Field(alias="affectedData")


class Metrics(NvdModel):
    """CVSS and SSVC scores published for a CVE.

    Missing metric groups are empty lists, not ``None``.
    """

    cvss_metric_v40: list[CvssMetricV40] = Field(default_factory=list, alias="cvssMetricV40")
    cvss_metric_v31: list[CvssMetricV31] = Field(default_factory=list, alias="cvssMetricV31")
    cvss_metric_v30: list[CvssMetricV30] = Field(default_factory=list, alias="cvssMetricV30")
    cvss_metric_v2: list[CvssMetricV2] = Field(default_factory=list, alias="cvssMetricV2")
    ssvc_v203: list[SsvcMetric] = Field(default_factory=list, alias="ssvcV203")


class CveRecord(NvdModel):
    """One CVE record from the ``cve`` object of an NVD 2.0 vulnerability.

    Required by the schema: ``id``, ``published``, ``lastModified``,
    ``descriptions``, and ``references``. Every other attribute defaults to
    empty or ``None`` when NVD omits it.
    """

    id: str
    published: datetime
    last_modified: datetime = Field(alias="lastModified")
    descriptions: list[LangString]
    references: list[Reference]
    source_identifier: str | None = Field(default=None, alias="sourceIdentifier")
    vuln_status: str | None = Field(default=None, alias="vulnStatus")
    evaluator_comment: str | None = Field(default=None, alias="evaluatorComment")
    evaluator_solution: str | None = Field(default=None, alias="evaluatorSolution")
    evaluator_impact: str | None = Field(default=None, alias="evaluatorImpact")
    cisa_exploit_add: date | None = Field(default=None, alias="cisaExploitAdd")
    cisa_action_due: date | None = Field(default=None, alias="cisaActionDue")
    cisa_required_action: str | None = Field(default=None, alias="cisaRequiredAction")
    cisa_vulnerability_name: str | None = Field(default=None, alias="cisaVulnerabilityName")
    cve_tags: list[CveTag] = Field(default_factory=list, alias="cveTags")
    metrics: Metrics = Field(default_factory=Metrics)
    weaknesses: list[Weakness] = Field(default_factory=list)
    configurations: list[Configuration] = Field(default_factory=list)
    vendor_comments: list[VendorComment] = Field(default_factory=list, alias="vendorComments")
    affected: list[Affected] = Field(default_factory=list)

    def description(self, lang: str = "en") -> str | None:
        """Return the description for ``lang``, or ``None`` when it is absent."""
        wanted = lang.lower()
        for entry in self.descriptions:
            if entry.lang.lower() == wanted:
                return entry.value
        return None

    @property
    def cwe_ids(self) -> list[str]:
        """Weakness description values, typically CWE or ``NVD-CWE-*`` ids."""
        found: list[str] = []
        for weakness in self.weaknesses:
            for entry in weakness.description:
                value = entry.value.strip()
                if value:
                    found.append(value)
        return found


class CveItem(NvdModel):
    """The ``vulnerabilities[]`` element, which wraps one :class:`CveRecord`."""

    cve: CveRecord


class CveListResponse(NvdModel):
    """A page of CVE results from ``/cves/2.0``.

    ``total_results`` is the size of the full match, not this page.
    ``cves`` is the unwrapped records in this page. An empty page is a
    successful response: ``total_results == 0`` and ``cves == []``.
    """

    results_per_page: int = Field(alias="resultsPerPage")
    start_index: int = Field(alias="startIndex")
    total_results: int = Field(alias="totalResults")
    format: str
    version: str
    timestamp: datetime
    vulnerabilities: list[CveItem]

    @property
    def cves(self) -> list[CveRecord]:
        """CVE records contained in this page, in NVD's order."""
        return [item.cve for item in self.vulnerabilities]


class CpeNameMatch(NvdModel):
    """A dictionary CPE name that satisfies a match string."""

    cpe_name: str = Field(alias="cpeName")
    cpe_name_id: str = Field(alias="cpeNameId")


class CpeMatchString(NvdModel):
    """One CPE match string from the CPE Match Criteria API."""

    criteria: str
    match_criteria_id: str = Field(alias="matchCriteriaId")
    created: datetime
    last_modified: datetime = Field(alias="lastModified")
    status: str
    version_start_excluding: str | None = Field(default=None, alias="versionStartExcluding")
    version_start_including: str | None = Field(default=None, alias="versionStartIncluding")
    version_end_excluding: str | None = Field(default=None, alias="versionEndExcluding")
    version_end_including: str | None = Field(default=None, alias="versionEndIncluding")
    cpe_last_modified: datetime | None = Field(default=None, alias="cpeLastModified")
    matches: list[CpeNameMatch] = Field(default_factory=list)


class CpeMatchStringItem(NvdModel):
    """The ``matchStrings[]`` element, which wraps one match string."""

    match_string: CpeMatchString = Field(alias="matchString")


class CpeMatchResponse(NvdModel):
    """A page of results from ``/cpematch/2.0``."""

    results_per_page: int = Field(alias="resultsPerPage")
    start_index: int = Field(alias="startIndex")
    total_results: int = Field(alias="totalResults")
    format: str
    version: str
    timestamp: datetime
    match_strings: list[CpeMatchStringItem] = Field(alias="matchStrings")

    @property
    def matches(self) -> list[CpeMatchString]:
        """Match strings contained in this page."""
        return [item.match_string for item in self.match_strings]
