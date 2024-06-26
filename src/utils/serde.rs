use std::fmt;

use anyhow::Result;
use regex::Regex;
use serde::{de, Serialize, Serializer};
use serde::Deserializer;

pub fn serialize_regex<S>(regex: &Regex, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    regex.as_str().serialize(serializer)
}

pub fn deserialize_regex<'d, D>(deserializer: D) -> Result<Regex, D::Error>
where
    D: Deserializer<'d>,
{
    struct V;
    impl<'d> de::Visitor<'d> for V {
        type Value = Regex;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(formatter, "a valid regex pattern")
        }

        fn visit_str<E>(self, value: &str) -> Result<Regex, E>
        where
            E: de::Error,
        {
            Regex::new(value).map_err(de::Error::custom)
        }
    }
    deserializer.deserialize_str(V)
}

pub fn serialize_regex_option<S>(regex: &Option<Regex>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match regex {
        Some(r) => r.as_str().serialize(serializer),
        None => serializer.serialize_none(),
    }
}

pub fn deserialize_regex_option<'d, D>(deserializer: D) -> Result<Option<Regex>, D::Error>
where
    D: Deserializer<'d>,
{
    struct V;
    impl<'d> de::Visitor<'d> for V {
        type Value = Option<Regex>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(formatter, "a valid regex pattern or null")
        }
        
        fn visit_none<E>(self) -> Result<Option<Regex>, E>
        where
            E: de::Error,
        {
            Ok(None)
        }

        fn visit_some<D>(self, deserializer: D) -> Result<Option<Regex>, D::Error>
        where
            D: Deserializer<'d>,
        {
            deserialize_regex(deserializer).map(Some)
        }
    }
    deserializer.deserialize_option(V)
}

pub fn serialize_regex_vec<S>(regexes: &Vec<Regex>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let patterns: Vec<String> = regexes.iter().map(|r| r.as_str().to_string()).collect();
    patterns.serialize(serializer)
}

pub fn deserialize_regex_vec<'d, D>(deserializer: D) -> Result<Vec<Regex>, D::Error>
where
    D: Deserializer<'d>,
{
    struct V;
    impl<'d> de::Visitor<'d> for V {
        type Value = Vec<Regex>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            write!(formatter, "an array of valid regex patterns")
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Vec<Regex>, A::Error>
        where
            A: de::SeqAccess<'d>,
        {
            let mut regexes = Vec::new();
            while let Some(value) = seq.next_element::<String>()? {
                regexes.push(Regex::new(&value).map_err(de::Error::custom)?);
            }
            Ok(regexes)
        }
    }

    deserializer.deserialize_any(V)
}
