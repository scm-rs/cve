use super::state::ConstValue;
use super::*;
use crate::common::{Description, ProblemType, Product, ProviderMetadata, Reference, Tag};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use std::ops::{Deref, DerefMut};
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct State;

const STATE_VALUE: &str = "PUBLISHED";

impl Serialize for State {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(STATE_VALUE)
    }
}

impl<'de> Deserialize<'de> for State {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer
            .deserialize_str(ConstValue(STATE_VALUE))
            .map(|()| State)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Metadata {
    pub state: State,

    #[serde(flatten)]
    pub common: common::Metadata,
}

impl Deref for Metadata {
    type Target = common::Metadata;

    fn deref(&self) -> &Self::Target {
        &self.common
    }
}

impl DerefMut for Metadata {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.common
    }
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Containers {
    pub cna: CnaContainer,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub adp: Vec<AdpContainer>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CnaContainer {
    #[serde(flatten)]
    pub common: common::CnaContainer,

    /// The date/time this CVE ID was associated with a vulnerability by a CNA.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub date_assigned: Option<Timestamp>,

    /// If known, the date/time the vulnerability was disclosed publicly.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub date_public: Option<Timestamp>,

    /// A title, headline, or a brief phrase summarizing the CVE record. Eg., Buffer overflow in Example Soft.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,

    /// A list of multi-lingual descriptions of the vulnerability. E.g., [PROBLEMTYPE] in [COMPONENT] in [VENDOR] [PRODUCT] [VERSION] on [PLATFORMS] allows [ATTACKER] to [IMPACT] via [VECTOR]. OR [COMPONENT] in [VENDOR] [PRODUCT] [VERSION] [ROOT CAUSE], which allows [ATTACKER] to [IMPACT] via [VECTOR].
    pub descriptions: Vec<Description>,

    /// List of affected products.
    pub affected: Vec<Product>,

    /// This is problem type information (e.g. CWE identifier). Must contain: At least one entry, can be text, OWASP, CWE, please note that while only one is required you can use more than one (or indeed all three) as long as they are correct). (CNA requirement: [PROBLEMTYPE]).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub problem_types: Vec<ProblemType>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub references: Vec<Reference>,

    /// Collection of impacts of this vulnerability.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub impacts: Vec<Impact>,

    /// Collection of impact scores with attribution.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub metrics: Vec<Metric>,

    /// Configurations required for exploiting this vulnerability.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub configurations: Vec<Description>,

    /// Workarounds and mitigations for this vulnerability.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub workarounds: Vec<Description>,

    /// Information about solutions or remediations available for this vulnerability.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub solutions: Vec<Description>,

    /// Information about exploits of the vulnerability.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exploits: Vec<Description>,

    /// This is timeline information for significant events about this vulnerability or changes to the CVE Record.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub timeline: Vec<Timeline>,

    /// Statements acknowledging specific people, organizations, or tools recognizing the work done in researching, discovering, remediating or helping with activities related to this CVE.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub credits: Vec<Credit>,

    /// This is the source information (who discovered it, who researched it, etc.) and optionally a chain of CNA information (e.g. the originating CNA and subsequent parent CNAs who have processed it before it arrives at the MITRE root).\n Must contain: IF this is in the root level it MUST contain a CNA_chain entry, IF this source entry is NOT in the root (e.g. it is part of a vendor statement) then it must contain at least one type of data entry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<Value>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<Tag>,

    /// List of taxonomy items related to the vulnerability.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub taxonomy_mappings: Vec<TaxonomyMapping>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Impact {
    /// CAPEC ID that best relates to this impact.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capec_id: Option<String>,

    /// Prose description of the impact scenario. At a minimum provide the description given by CAPEC.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub descriptions: Vec<Description>,
}

/// This is impact type information (e.g. a text description, CVSSv2, CVSSv3, CVSSv4, etc.). Must contain: At least one entry, can be text, CVSSv2, CVSSv3, others may be added.
#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Metric {
    /// Name of the scoring format. This provides a bit of future proofing. Additional properties are not prohibited, so this will support the inclusion of proprietary formats. It also provides an easy future conversion mechanism when future score formats become part of the schema. example: cvssV44, format = 'cvssV44', other = cvssV4_4 JSON object. In the future, the other properties can be converted to score properties when they become part of the schema.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,

    /// Description of the scenarios this metrics object applies to. If no specific scenario is given, GENERAL is used as the default and applies when no more specific metric matches.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scenarios: Vec<Scenario>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(rename = "cvssV4_0")]
    pub cvss_v4_0: Option<Value>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(rename = "cvssV3_1")]
    pub cvss_v3_1: Option<Value>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(rename = "cvssV3_0")]
    pub cvss_v3_0: Option<Value>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(rename = "cvssV2_0")]
    pub cvss_v2_0: Option<Value>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub other: Option<OtherMetric>,
}

/// A non-standard impact description, may be prose or JSON block.
#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OtherMetric {
    /// Name of the non-standard impact metrics format used.
    pub r#type: String,
    /// JSON object not covered by another metrics format.
    pub content: Value,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Scenario {
    #[serde(rename = "lang")]
    pub language: String,

    /// Description of the scenario this metrics object applies to. If no specific scenario is given, GENERAL is used as the default and applies when no more specific metric matches.
    #[serde(default = "Scenario::default_value")]
    pub value: String,
}

impl Scenario {
    pub fn default_value() -> String {
        "GENERAL".to_string()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Timeline {
    /// Timestamp representing when the event in the timeline occurred. The timestamp format is based on RFC3339 and ISO ISO8601, with an optional timezone. yyyy-MM-ddTHH:mm:ssZZZZ - if the timezone offset is not given, GMT (0000) is assumed.
    pub time: Timestamp,

    /// The language used in the description of the event. The language field is included so that CVE Records can support translations. The value must be a BCP 47 language code.
    #[serde(rename = "lang")]
    pub language: String,

    /// A summary of the event.
    pub value: String,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Credit {
    /// The language used when describing the credits. The language field is included so that CVE Records can support translations. The value must be a BCP 47 language code.
    #[serde(rename = "lang")]
    pub language: String,

    pub value: String,

    /// UUID of the user being credited if present in the CVE User Registry (optional). This UUID can be used to lookup the user record in the user registry service.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<Uuid>,

    /// Type or role of the entity being credited (optional).
    #[serde(default, skip_serializing_if = "is_default_credit_type")]
    pub r#type: CreditType,
}

fn is_default_credit_type(value: &CreditType) -> bool {
    *value == CreditType::Finder
}

/// Type or role of the entity being credited.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CreditType {
    /// identifies the vulnerability.
    #[default]
    Finder,
    /// notifies the vendor of the vulnerability to a CNA.
    Reporter,
    /// validates the vulnerability to ensure accuracy or severity.
    Analyst,
    /// facilitates the coordinated response process.
    Coordinator,
    /// prepares a code change or other remediation plans.
    #[serde(rename = "remediation developer")]
    RemediationDeveloper,
    /// reviews vulnerability remediation plans or code changes for effectiveness and completeness.
    #[serde(rename = "remediation reviewer")]
    RemediationReviewer,
    /// tests and verifies the vulnerability or its remediation.
    #[serde(rename = "remediation verifier")]
    RemediationVerifier,
    /// names of tools used in vulnerability discovery or identification.
    Tool,
    /// supports the vulnerability identification or remediation activities.
    Sponsor,
    Other,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TaxonomyMapping {
    /// The name of the taxonomy.
    #[serde(rename = "taxonomyName")]
    pub name: String,

    /// The version of taxonomy the identifiers come from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(rename = "taxonomyVersion")]
    pub version: Option<String>,

    /// List of relationships to the taxonomy for the vulnerability.  Relationships can be between the taxonomy and the CVE or two taxonomy items.
    #[serde(rename = "taxonomyRelations")]
    pub relations: Vec<TaxonomyRelation>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TaxonomyRelation {
    /// Identifier of the item in the taxonomy.  Used as the subject of the relationship.
    #[serde(rename = "taxonomyId")]
    pub id: String,

    /// A description of the relationship.
    #[serde(rename = "relationshipName")]
    pub name: String,

    /// The target of the relationship.  Can be the CVE ID or another taxonomy identifier.
    #[serde(rename = "relationshipValue")]
    pub value: String,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AdpContainer {
    pub provider_metadata: ProviderMetadata,

    /// If known, the date/time the vulnerability was disclosed publicly.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub date_public: Option<Timestamp>,

    /// A title, headline, or a brief phrase summarizing the information in an ADP container.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,

    /// A list of multi-lingual descriptions of the vulnerability. E.g., [PROBLEMTYPE] in [COMPONENT] in [VENDOR] [PRODUCT] [VERSION] on [PLATFORMS] allows [ATTACKER] to [IMPACT] via [VECTOR]. OR [COMPONENT] in [VENDOR] [PRODUCT] [VERSION] [ROOT CAUSE], which allows [ATTACKER] to [IMPACT] via [VECTOR].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub descriptions: Vec<Description>,

    /// List of affected products.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub affected: Vec<Product>,

    /// This is problem type information (e.g. CWE identifier). Must contain: At least one entry, can be text, OWASP, CWE, please note that while only one is required you can use more than one (or indeed all three) as long as they are correct). (CNA requirement: [PROBLEMTYPE]).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub problem_types: Vec<ProblemType>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub references: Vec<Reference>,

    /// Collection of impacts of this vulnerability.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub impacts: Vec<Impact>,

    /// Collection of impact scores with attribution.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub metrics: Vec<Metric>,

    /// Configurations required for exploiting this vulnerability.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub configurations: Vec<Description>,

    /// Workarounds and mitigations for this vulnerability.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub workarounds: Vec<Description>,

    /// Information about solutions or remediations available for this vulnerability.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub solutions: Vec<Description>,

    /// Information about exploits of the vulnerability.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exploits: Vec<Description>,

    /// This is timeline information for significant events about this vulnerability or changes to the CVE Record.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub timeline: Vec<Timeline>,

    /// Statements acknowledging specific people, organizations, or tools recognizing the work done in researching, discovering, remediating or helping with activities related to this CVE.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub credits: Vec<Credit>,

    /// This is the source information (who discovered it, who researched it, etc.) and optionally a chain of CNA information (e.g. the originating CNA and subsequent parent CNAs who have processed it before it arrives at the MITRE root).\n Must contain: IF this is in the root level it MUST contain a CNA_chain entry, IF this source entry is NOT in the root (e.g. it is part of a vendor statement) then it must contain at least one type of data entry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<Value>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<Tag>,

    /// List of taxonomy items related to the vulnerability.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub taxonomy_mappings: Vec<TaxonomyMapping>,
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn parse_metadata() {
        let input = r#"
{
    "assignerOrgId": "8254265b-2729-46b6-b9e3-3dfca2d5bfca",
    "assignerShortName": "mitre",
    "cveId": "CVE-2013-7088",
    "datePublished": "2019-11-15T14:19:48",
    "dateReserved": "2013-12-12T00:00:00",
    "dateUpdated": "2019-11-15T14:19:48",
    "state": "PUBLISHED"
}

"#;
        let _metadata: Metadata = serde_json::from_str(input).unwrap();
    }

    #[test]
    fn default_value_returns_general() {
        let value = Scenario::default_value();
        assert_eq!(value, "GENERAL");
    }
}
