use serde::{de::Visitor, ser::Error, Deserialize, Deserializer, Serialize, Serializer};
use std::{fmt::Formatter, num::NonZeroU8};
use time::{
    format_description::well_known::{
        iso8601::{Config, EncodedConfig, FormattedComponents, TimePrecision},
        Iso8601,
    },
    OffsetDateTime, PrimitiveDateTime,
};

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Timestamp {
    /// Full offset information
    Offset(OffsetDateTime),
    /// No offset information
    Primitive(PrimitiveDateTime),
}

impl Timestamp {
    pub fn assume_utc(self) -> OffsetDateTime {
        match self {
            Self::Offset(value) => value,
            Self::Primitive(value) => value.assume_utc(),
        }
    }
}

impl From<OffsetDateTime> for Timestamp {
    fn from(value: OffsetDateTime) -> Self {
        Self::Offset(value)
    }
}

impl From<PrimitiveDateTime> for Timestamp {
    fn from(value: PrimitiveDateTime) -> Self {
        Self::Primitive(value)
    }
}

impl Serialize for Timestamp {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        const OFFSET_FORMAT: EncodedConfig = Config::DEFAULT
            .set_time_precision(TimePrecision::Second {
                decimal_digits: Some(unsafe { NonZeroU8::new_unchecked(3) }),
            })
            .encode();

        const PRIMITIVE_FORMAT: EncodedConfig = Config::DEFAULT
            .set_formatted_components(FormattedComponents::DateTime)
            .set_time_precision(TimePrecision::Second {
                decimal_digits: Some(unsafe { NonZeroU8::new_unchecked(3) }),
            })
            .encode();

        match self {
            Self::Offset(value) => {
                let value = value
                    .format(&Iso8601::<OFFSET_FORMAT>)
                    .map_err(|err| Error::custom(format!("Failed to encode timestamp: {err}")))?;
                serializer.serialize_str(&value)
            }
            Self::Primitive(value) => {
                let value = value
                    .format(&Iso8601::<PRIMITIVE_FORMAT>)
                    .map_err(|err| Error::custom(format!("Failed to encode timestamp: {err}")))?;
                serializer.serialize_str(&value)
            }
        }
    }
}

impl<'de> Deserialize<'de> for Timestamp {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct TimestampVisitor;

        impl Visitor<'_> for TimestampVisitor {
            type Value = Timestamp;

            fn expecting(&self, formatter: &mut Formatter) -> std::fmt::Result {
                formatter.write_str("an ISO 8601 timestamp with our without timezone")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                if let Ok(result) = OffsetDateTime::parse(v, &Iso8601::PARSING) {
                    return Ok(result.into());
                }
                if let Ok(result) = PrimitiveDateTime::parse(v, &Iso8601::PARSING) {
                    return Ok(result.into());
                }

                Err(E::custom(format!(
                    "unable to parse '{v}' as ISO 8601 timestamp"
                )))
            }
        }

        deserializer.deserialize_str(TimestampVisitor)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use time::macros::datetime;

    #[test]
    pub fn serialize_timestamp_offset() {
        assert_eq!(
            &serde_json::to_string(&Timestamp::from(datetime!(2020-01-02 12:34 ).assume_utc()))
                .unwrap(),
            r#""2020-01-02T12:34:00.000Z""#
        );

        assert_eq!(
            &serde_json::to_string(&Timestamp::from(datetime!(2020-01-02 12:34 +01:00))).unwrap(),
            r#""2020-01-02T12:34:00.000+01:00""#
        );
    }

    #[test]
    pub fn serialize_timestamp_primitive() {
        assert_eq!(
            &serde_json::to_string(&Timestamp::from(datetime!(2020-01-02 12:34))).unwrap(),
            r#""2020-01-02T12:34:00.000""#
        );
    }

    #[test]
    pub fn deserialize_invalid_timestamp() {
        let invalid = r#""invalid-timestamp-foo""#;
        let err = serde_json::from_str::<Timestamp>(invalid).unwrap_err();
        assert!(err.to_string().contains("unable to parse"));
    }

    #[test]
    pub fn deserialize_timestamp_primitive() {
        let s = r#""2020-01-02T12:34:00.000""#;
        let ts = serde_json::from_str(s).unwrap();
        assert!(matches!(ts, Timestamp::Primitive(_)));
    }

    #[test]
    pub fn deserialize_timestamp_offset() {
        let s = r#""2020-01-02T12:34:00.000Z""#;
        let ts = serde_json::from_str(s).unwrap();
        assert!(matches!(ts, Timestamp::Offset(_)));
    }

    #[test]
    pub fn assume_utc_for_offset_and_primitive() {
        let offset_datetime = datetime!(2020-01-02 12:34 +01:00);
        let primitive_datetime = datetime!(2020-01-02 12:34);

        let offset_ts = Timestamp::from(offset_datetime);
        let primitive_ts = Timestamp::from(primitive_datetime);

        assert_eq!(offset_ts.assume_utc(), offset_datetime);
        assert_eq!(primitive_ts.assume_utc(), primitive_datetime.assume_utc());
    }
}
