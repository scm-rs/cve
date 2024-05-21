use super::*;
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Metadata {
    #[serde(rename = "cveId")]
    pub id: String,
    pub assigner_org_id: Uuid,

    #[serde(default = "default_serial", skip_serializing_if = "is_default_serial")]
    pub serial: NonZeroUsize,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assigner_short_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub date_reserved: Option<Timestamp>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub date_published: Option<Timestamp>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub date_updated: Option<Timestamp>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CnaContainer {
    pub provider_metadata: ProviderMetadata,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Product {
    /// Name of the organization, project, community, individual, or user that created or maintains this product or hosted service. Can be 'N/A' if none of those apply. When collectionURL and packageName are used, this field may optionally represent the user or account within the package collection associated with the package.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vendor: Option<String>,

    /// Name of the affected product.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub product: Option<String>,

    /// URL identifying a package collection (determines the meaning of packageName).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(rename = "collectionURL")]
    pub collection_url: Option<String>,

    /// Name or identifier of the affected software package as used in the package collection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub package_name: Option<String>,

    /// Affected products defined by CPE. This is an array of CPE values (vulnerable and not), we use an array so that we can make multiple statements about the same version and they are separate (if we used a JSON object we'd essentially be keying on the CPE name and they would have to overlap). Also, this allows things like cveDataVersion or cveDescription to be applied directly to the product entry. This also allows more complex statements such as \"Product X between versions 10.2 and 10.8\" to be put in a machine-readable format. As well since multiple statements can be used multiple branches of the same product can be defined here.
    // FIXME: use CPE type
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cpes: Vec<String>,

    /// A list of the affected components, features, modules, sub-components, sub-products, APIs, commands, utilities, programs, or functionalities (optional).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub modules: Vec<String>,

    /// A list of the affected source code files (optional).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub program_files: Vec<String>,

    /// A list of the affected source code files (optional).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub program_routines: Vec<ProgramRoutine>,

    /// List of specific platforms if the vulnerability is only relevant in the context of these platforms (optional). Platforms may include execution environments, operating systems, virtualization technologies, hardware models, or computing architectures. The lack of this field or an empty array implies that the other fields are applicable to all relevant platforms.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub platforms: Vec<String>,

    /// The URL of the source code repository, for informational purposes and/or to resolve git hash version ranges.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(rename = "repo")]
    pub repository: Option<String>,

    /// The default status for versions that are not otherwise listed in the versions list. If not specified, defaultStatus defaults to 'unknown'. Versions or defaultStatus may be omitted, but not both.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_status: Option<Status>,

    /// Set of product versions or version ranges related to the vulnerability. The versions satisfy the CNA Rules [8.1.2 requirement](https://cve.mitre.org/cve/cna/rules.html#section_8-1_cve_entry_information_requirements). Versions or defaultStatus may be omitted, but not both.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub versions: Vec<Version>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
#[serde(untagged)]
pub enum Version {
    Single(Single),
    #[serde(rename_all = "camelCase")]
    Range(Range),
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct Single {
    /// The single version being described, or the version at the start of the range. By convention, typically 0 denotes the earliest possible version.
    pub version: String,
    /// The vulnerability status for the version or range of versions. For a range, the status may be refined by the 'changes' list.
    pub status: Status,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version_type: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Range {
    /// The single version being described, or the version at the start of the range. By convention, typically 0 denotes the earliest possible version.
    pub version: String,
    #[serde(flatten)]
    pub range: VersionRange,
    /// The vulnerability status for the version or range of versions. For a range, the status may be refined by the 'changes' list.
    pub status: Status,
    pub version_type: String,
    /// A list of status changes that take place during the range. The array should be sorted in increasing order by the 'at' field, according to the versionType, but clients must re-sort the list themselves rather than assume it is sorted.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub changes: Vec<Change>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Change {
    /// The version at which a status change occurs.
    pub at: String,
    /// The new status in the range starting at the given version.
    pub status: Status,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub enum VersionRange {
    /// The non-inclusive upper limit of the range. This is the least version NOT in the range. The usual version syntax is expanded to allow a pattern to end in an asterisk `(*)`, indicating an arbitrarily large number in the version ordering. For example, `{version: 1.0 lessThan: 1.*}` would describe the entire 1.X branch for most range kinds, and `{version: 2.0, lessThan: *}` describes all versions starting at 2.0, including 3.0, 5.1, and so on. Only one of lessThan and lessThanOrEqual should be specified.
    LessThan(String),
    /// The inclusive upper limit of the range. This is the greatest version contained in the range. Only one of lessThan and lessThanOrEqual should be specified. For example, `{version: 1.0, lessThanOrEqual: 1.3}` covers all versions from 1.0 up to and including 1.3.
    LessThanOrEqual(String),
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Status {
    Affected,
    Unaffected,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProgramRoutine {
    pub name: String,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Description {
    #[serde(rename = "lang")]
    pub language: String,

    /// Plain text description.
    pub value: String,

    /// Supporting media data for the description such as markdown, diagrams, .. (optional). Similar to RFC 2397 each media object has three main parts: media type, media data value, and an optional boolean flag to indicate if the media data is base64 encoded.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub supporting_media: Vec<SupportingMedia>,
}

/// Supporting media
#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SupportingMedia {
    /// RFC2046 compliant IANA Media type for eg., text/markdown, text/html.
    pub r#type: String,

    /// Supporting media content, up to 16K. If base64 is true, this field stores base64 encoded data.
    pub value: String,

    /// If true then the value field contains the media data encoded in base64. If false then the value field contains the UTF-8 media content.
    #[serde(default, skip_serializing_if = "is_false")]
    pub base64: bool,
}

pub fn is_false(value: &bool) -> bool {
    *value == false
}

/// Details related to the information container provider (CNA or ADP).
#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderMetadata {
    /// The container provider's organizational UUID.
    pub org_id: Uuid,

    /// The container provider's organizational short name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub short_name: Option<String>,

    /// Timestamp to be set by the system of record at time of submission. If dateUpdated is provided to the system of record it will be replaced by the current timestamp at the time of submission.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub date_updated: Option<Timestamp>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProblemType {
    pub descriptions: Vec<ProblemTypeDescription>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProblemTypeDescription {
    #[serde(rename = "lang")]
    pub language: String,

    /// Text description of problemType, or title from CWE or OWASP.
    pub description: String,

    /// CWE ID of the CWE that best describes this problemType entry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwe_id: Option<String>,

    /// Problemtype source, text, OWASP, CWE, etc.,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub r#type: Option<String>,

    /// This is reference data in the form of URLs or file objects (uuencoded and embedded within the JSON file, exact format to be decided, e.g. we may require a compressed format so the objects require unpacking before they are \"dangerous\").
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub references: Vec<Reference>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Reference {
    /// The uniform resource locator (URL), according to [RFC 3986](https://tools.ietf.org/html/rfc3986#section-1.1.3), that can be used to retrieve the referenced resource.
    pub url: String,

    /// User created name for the reference, often the title of the page.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// An array of one or more tags that describe the resource referenced by 'url'.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<Tag>,
}

pub type Tag = String;

#[cfg(test)]
mod test {
    use super::*;
    use serde_json::json;

    #[test]
    fn parse_version() {
        let input = r#"
{
    "lessThan": "5.7",
    "status": "affected",
    "version": "unspecified",
    "versionType": "custom"
}
"#;

        let _version: Version = serde_json::from_str(input).unwrap();
    }

    #[test]
    fn write_version() {
        let json = serde_json::to_value(Version::Range(Range {
            range: VersionRange::LessThan("5.7".to_string()),
            version_type: "custom".to_string(),
            version: "unspecified".to_string(),
            status: Status::Affected,
            changes: vec![],
        }))
        .unwrap();

        assert_eq!(
            json!({
                "lessThan": "5.7",
                "status": "affected",
                "version": "unspecified",
                "versionType": "custom"
            }),
            json
        );
    }
}
