use std::{env, fs::File, io::Read};

mod mdict {
    use std::{result, string::FromUtf16Error};

    use nom::{
        combinator::map,
        error::{ErrorKind, ParseError},
        multi::length_count,
        number::streaming::{be_u32, le_u16, le_u32},
        sequence::tuple,
        IResult, Parser,
    };
    use serde::Deserialize;

    use thiserror::Error;

    #[derive(Error, Debug)]
    pub enum Error {
        #[error("{0}")]
        De(#[from] quick_xml::DeError),
        #[error("{0}")]
        FromUtf16(#[from] FromUtf16Error),
        #[error("NomError")]
        Nom(ErrorKind),
    }

    impl<I> ParseError<I> for Error {
        fn from_error_kind(_input: I, kind: ErrorKind) -> Self {
            Error::Nom(kind)
        }

        fn append(_: I, _: ErrorKind, other: Self) -> Self {
            other
        }
    }

    type Result<T> = result::Result<T, Error>;
    type NomResult<I, O> = nom::IResult<I, O, Error>;

    #[derive(Debug, Deserialize, PartialEq)]
    struct DictMeta {
        #[serde(rename = "GeneratedByEngineVersion")]
        generated_by_engine_version: f64,
        #[serde(rename = "RequiredEngineVersion")]
        required_engine_version: f64,
        #[serde(rename = "Format")]
        format: String,
        #[serde(rename = "KeyCaseSensitive")]
        key_case_sensitive: String,
        #[serde(rename = "StripKey")]
        strip_key: Option<String>,
        #[serde(rename = "Encrypted")]
        encrypted: String,
        #[serde(rename = "RegisterBy")]
        register_by: Option<String>,
        #[serde(rename = "Description")]
        description: String,
        #[serde(rename = "Title")]
        title: String,
        #[serde(rename = "Encoding")]
        encoding: String,
        #[serde(rename = "CreationDate")]
        creation_date: Option<String>,
        #[serde(rename = "Compact")]
        compact: String,
        #[serde(rename = "Compat")]
        compat: String,
        #[serde(rename = "Left2Right")]
        left2right: String,
        #[serde(rename = "DataSourceFormat")]
        data_source_format: String,
        #[serde(rename = "StyleSheet")]
        style_sheet: String,
    }

    impl DictMeta {
        fn is_ver2(&self) -> bool {
            self.required_engine_version >= 2.0
        }
    }

    macro_rules! nom_return {
        ($in_:tt, $output_t:ty, $x:expr) => {
            match || -> Result<$output_t> { Ok($x) }() {
                Ok(v) => Ok(($in_, v)),
                Err(e) => Err(nom::Err::Error(e)),
            }
        };
    }

    pub fn cond_number<I, E, O1, O2, F1, F2>(
        cond: bool,
        mut f1: F1,
        mut f2: F2,
    ) -> impl FnMut(I) -> IResult<I, O1, E>
    where
        E: ParseError<I>,
        F1: Parser<I, O1, E>,
        F2: Parser<I, O2, E>,
        O1: From<O2>,
    {
        move |in_: I| {
            if cond {
                f1.parse(in_)
            } else {
                f2.parse(in_).map(|(i, o)| (i, O1::from(o)))
            }
        }
    }

    fn dict_meta(in_: &[u8]) -> NomResult<&[u8], DictMeta> {
        let (in_, (dict_meta, _checksum)) =
            tuple((length_count(map(be_u32, |i| i / 2), le_u16), le_u32))(in_)?;

        nom_return!(in_, DictMeta, {
            quick_xml::de::from_str::<DictMeta>(&String::from_utf16(&dict_meta)?)?
        })
    }

    pub mod mdx {
        use std::collections::HashMap;

        use nom::{
            combinator::{cond, map},
            multi::length_count,
            number::streaming::{be_u32, be_u64, le_u32},
            sequence::tuple,
        };

        use super::{cond_number, dict_meta, DictMeta, NomResult, Result};

        #[derive(Debug)]
        pub struct Mdx {
            dict_meta: DictMeta,
        }

        #[derive(Debug)]
        struct KeyBlockHeader {
            n_blocks: u64,
            n_entries: u64,
            nb_decompressed: Option<u64>,
            nb_block_info: u64,
            nb_blocks: u64,
            checksum: Option<u32>,
        }

        fn key_block<'a>(in_: &'a [u8], meta: &DictMeta) -> NomResult<&'a [u8], KeyMap> {
            let is_ver2 = meta.is_ver2();

            let (in_, header) = map(
                tuple((
                    cond_number(is_ver2, be_u64, be_u32),
                    cond_number(is_ver2, be_u64, be_u32),
                    cond(is_ver2, be_u64),
                    cond_number(is_ver2, be_u64, be_u32),
                    cond_number(is_ver2, be_u64, be_u32),
                    cond(is_ver2, le_u32),
                )),
                |(n_blocks, n_entries, nb_decompressed, nb_block_info, nb_blocks, checksum)| {
                    KeyBlockHeader {
                        n_entries,
                        n_blocks,
                        nb_decompressed,
                        nb_block_info,
                        nb_blocks,
                        checksum,
                    }
                },
            )(in_)?;

            let (in_, km) = mdx_key_block_info(in_, &header, meta)?;

            Ok((in_, KeyMap::new()))
        }

        struct KeyBlockInfo {
            n_entries: u32,
            head: u64,
            tail: u64,
            nb_compressed: u64,
            nb_decompressed: u64,
        }

        type KeyMap = HashMap<String, u64>;

        fn mdx_key_block_info<'a>(
            in_: &'a [u8],
            head: &KeyBlockHeader,
            meta: &DictMeta,
        ) -> NomResult<&'a [u8], KeyMap> {
            // if (meta.is_ver2()) {

            // }
            tuple(be_u32, lencount())(in_);

            Ok((in_, KeyMap::new()))
        }

        pub fn parse(in_: &[u8]) -> NomResult<&[u8], Mdx> {
            let (in_, dict_meta) = dict_meta(in_)?;
            let (in_, key_block) = key_block(in_, &dict_meta)?;

            nom_return!(in_, Mdx, Mdx { dict_meta })
        }
    }
}

fn main() {
    let dict_path = env::args().nth(1).unwrap();
    let mut file = File::open(dict_path).unwrap();
    let mut buf = Vec::new();
    file.read_to_end(&mut buf).unwrap();

    println!("{:?}", mdict::mdx::parse(&buf).unwrap().1);

    // let mdx = mdict::Mdx::parse(Path::new(&dict));

    // match mdx {
    //     Ok(mdx) => {
    //         let query = std::env::args().nth(2).unwrap();
    //         println!("query: {}", query);
    //         mdx.search(query)
    //             .iter()
    //             .map(|item| (item.0.clone(), from_read(Cursor::new(&item.1), 100)))
    //             .for_each(|item| {
    //                 println!("{}", item.1);
    //             })
    //     }
    //     Err(e) => println!("{:?}", e),
    // }
}
