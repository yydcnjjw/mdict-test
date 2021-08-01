use std::{env, fs::File, io::Read};

mod mdict {
    use std::{result, string::FromUtf16Error};

    use nom::{
        combinator::map,
        error::{ErrorKind, ParseError},
        multi::length_count,
        number::streaming::{be_u32, be_u64, le_u16, le_u32},
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

    pub fn cond_if<I, E, O1, O2, F1, F2>(
        cond: bool,
        mut f1: F1,
        mut f2: F2,
        map: impl Fn(O2) -> O1,
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
                f2.parse(in_).map(|(i, o)| (i, map(o)))
            }
        }
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
        use std::{
            collections::HashMap,
            io::{Cursor, Read},
            ops::RangeFrom,
        };

        use byteorder::{LittleEndian, WriteBytesExt};

        use flate2::read::ZlibDecoder;
        use nom::{
            combinator::{cond, map},
            error::ParseError,
            multi::{count, length_count, length_data},
            number::streaming::{be_u16, be_u32, be_u64, be_u8, le_u16, le_u32, le_u8},
            sequence::tuple,
            IResult, InputIter, InputLength, Slice,
        };
        use ripemd128::{Digest, Ripemd128};

        use super::{cond_if, cond_number, dict_meta, DictMeta, NomResult, Result};

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

            println!("{:?}", header);

            let (in_, infos) = mdx_key_block_info(in_, &header, meta)?;

            Ok((in_, KeyMap::new()))
        }

        #[derive(Debug)]
        struct KeyBlockInfo {
            n_entries: u64,
            head: String,
            tail: String,
            nb_compressed: u64,
            nb_decompressed: u64,
        }

        type KeyMap = HashMap<String, u64>;

        fn unzip_mdx_key_block_info(data: &[u8], checksum: u32) -> Result<Vec<u8>> {
            let key: Vec<u8>;
            {
                let mut vec = Vec::with_capacity(8);
                // TODO: unwrap
                vec.write_u32::<LittleEndian>(checksum).unwrap();
                vec.write_u32::<LittleEndian>(0x3695).unwrap();

                let mut hasher = Ripemd128::new();
                hasher.input(vec);
                key = hasher.result().to_vec();
            }

            let mut prev = 0x36;
            let data = data
                .iter()
                .enumerate()
                .map(|(i, b)| {
                    let mut t = (*b >> 4 | *b << 4) & 0xff;
                    t = t ^ prev ^ (i & 0xff) as u8 ^ key[i % key.len()];

                    prev = *b;
                    t
                })
                .collect::<Vec<u8>>();

            let mut input = Vec::new();

            {
                let mut decoder = ZlibDecoder::new(Cursor::new(data));
                // TODO: unwrap
                decoder.read_to_end(&mut input).unwrap();
            }

            Ok(input)
        }

        fn mdx_key_block_info_key<I, E>(
            meta: &DictMeta,
        ) -> impl FnMut(I) -> IResult<I, String, E>
        where
            I: Clone + Slice<RangeFrom<usize>> + InputIter<Item = u8> + InputLength,
            E: ParseError<I>,
        {
            let is_ver2 = meta.is_ver2();
            let is_utf8 = meta.encoding == "UTF-8";

            cond_if(
                is_utf8,
                map(
                    length_count(
                        map(cond_number(is_ver2, be_u16, be_u8), move |v| {
                            if is_ver2 {
                                v + 1
                            } else {
                                v
                            }
                        }),
                        le_u8,
                    ),
                    |v| String::from_utf8(v).unwrap_or_default(),
                ),
                map(
                    length_count(
                        map(cond_number(is_ver2, be_u16, be_u8), move |v| {
                            if is_ver2 {
                                v + 1
                            } else {
                                v
                            }
                        }),
                        le_u16,
                    ),
                    |v| String::from_utf16(&v).unwrap_or_default(),
                ),
                |o| o,
            )
        }

        fn mdx_key_block_info_normal<'a>(
            in_: &'a [u8],
            header: &KeyBlockHeader,
            meta: &DictMeta,
        ) -> NomResult<&'a [u8], Vec<KeyBlockInfo>> {
            let is_ver2 = meta.is_ver2();

            let (in_, infos) = count(
                map(
                    tuple((
                        cond_number(is_ver2, be_u64, be_u32),
                        mdx_key_block_info_key(meta),
                        mdx_key_block_info_key(meta),
                        cond_number(is_ver2, be_u64, be_u32),
                        cond_number(is_ver2, be_u64, be_u32),
                    )),
                    |(n_entries, head, tail, nb_compressed, nb_decompressed): (
                        u64,
                        String,
                        String,
                        u64,
                        u64,
                    )| KeyBlockInfo {
                        n_entries,
                        head,
                        tail,
                        nb_compressed,
                        nb_decompressed,
                    },
                ),
                header.n_blocks as usize,
            )(in_)?;

            Ok((in_, infos))
        }

        fn mdx_key_block_info<'a>(
            in_: &'a [u8],
            header: &KeyBlockHeader,
            meta: &DictMeta,
        ) -> NomResult<&'a [u8], Vec<KeyBlockInfo>> {
            let is_ver2 = meta.is_ver2();

            let (in_, infos) = if is_ver2 {
                let (in_, (_, checksum, data)) = tuple((
                    le_u32,
                    le_u32,
                    count(le_u8, header.nb_block_info as usize - 8),
                ))(in_)?;

                let input = unzip_mdx_key_block_info(&data, checksum).unwrap();

                let (_, infos) = mdx_key_block_info_normal(&input, header, meta)?;
                (in_, infos)
            } else {
                mdx_key_block_info_normal(in_, header, meta)?
            };

            infos.iter().for_each(|info| println!("{:?}", info));

            Ok((in_, infos))
        }

        // fn mdx_key_map<'a>(
        //     in_: &'a [u8],
        //     infos: Vec<KeyBlockInfo>,
        //     meta: &DictMeta,
        // ) -> NomResult<&'a [u8], KeyMap> {
        // }

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
