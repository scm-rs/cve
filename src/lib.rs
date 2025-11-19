mod timestamp;

pub use timestamp::*;

pub mod common;
pub mod published;
pub mod rejected;

use std::num::NonZeroUsize;

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
#[serde(untagged)]
#[allow(clippy::large_enum_variant)]
pub enum Cve {
    #[serde(rename_all = "camelCase")]
    Published(Published),
    #[serde(rename_all = "camelCase")]
    Rejected(Rejected),
}

impl Cve {
    pub fn id(&self) -> &str {
        &self.common_metadata().id
    }

    pub fn common_metadata(&self) -> &common::Metadata {
        match self {
            Self::Published(cve) => &cve.metadata.common,
            Self::Rejected(cve) => &cve.metadata.common,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Published {
    pub data_type: DataType,
    pub data_version: DataVersion,
    #[serde(rename = "cveMetadata")]
    pub metadata: published::Metadata,
    pub containers: published::Containers,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Rejected {
    pub data_type: DataType,
    pub data_version: DataVersion,
    #[serde(rename = "cveMetadata")]
    pub metadata: rejected::Metadata,
    pub containers: rejected::Containers,
}

const fn default_serial() -> NonZeroUsize {
    unsafe { NonZeroUsize::new_unchecked(1) }
}

fn is_default_serial(value: &NonZeroUsize) -> bool {
    *value == default_serial()
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum DataVersion {
    #[serde(rename = "5.0")]
    V5_0,
    #[serde(rename = "5.1")]
    V5_1,
    #[serde(rename = "5.2")]
    V5_2,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum DataType {
    #[serde(rename = "CVE_RECORD")]
    Record,
}

mod state {
    use serde::de::*;
    use std::fmt::Formatter;

    pub struct ConstValue(pub &'static str);

    impl Visitor<'_> for ConstValue {
        type Value = ();

        fn expecting(&self, formatter: &mut Formatter) -> std::fmt::Result {
            write!(formatter, "Must have a string value of '{}'", self.0)
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: Error,
        {
            match v == self.0 {
                true => Ok(()),
                false => Err(E::custom(format!("Value must be: {} (was: {})", self.0, v))),
            }
        }
    }
}
