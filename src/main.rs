use std::{env, fs::File, io::Read};

mod mdict {
    use std::{io, result, string::FromUtf16Error};

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
        #[error("{0}")]
        IO(#[from] io::Error),
        #[error("{0}")]
        LZO(#[from] minilzo_rs::Error),
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
    pub struct DictMeta {
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

    pub fn cond_if<I, E, O, F1, F2>(
        cond: bool,
        mut f1: F1,
        mut f2: F2,
    ) -> impl FnMut(I) -> IResult<I, O, E>
    where
        E: ParseError<I>,
        F1: Parser<I, O, E>,
        F2: Parser<I, O, E>,
    {
        move |in_: I| {
            if cond {
                f1.parse(in_)
            } else {
                f2.parse(in_)
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
            bytes::streaming::tag,
            combinator::{cond, map},
            error::ParseError,
            multi::{count, length_count, many_till},
            number::streaming::{be_u16, be_u32, be_u64, be_u8, le_u16, le_u32, le_u8},
            sequence::tuple,
            AsBytes, Compare, IResult, InputIter, InputLength, InputTake, Parser, Slice,
        };
        use ripemd128::{Digest, Ripemd128};

        use super::{cond_if, dict_meta, DictMeta, NomResult, Result};

        #[derive(Debug)]
        pub struct Mdx {
            pub dict_meta: DictMeta,
            pub keymap: KeyMap,
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

        fn mdx_number<I, E>(meta: &DictMeta) -> impl FnMut(I) -> IResult<I, u64, E>
        where
            I: Slice<RangeFrom<usize>> + InputIter<Item = u8> + InputLength,
            E: ParseError<I>,
        {
            cond_if(meta.is_ver2(), be_u64, map(be_u32, |v| v as u64))
        }

        const U8NULL: &'static [u8] = &[0u8];
        const U16NULL: &'static [u8] = &[0u8, 0u8];

        fn mdx_string<I, E>(meta: &DictMeta) -> impl FnMut(I) -> IResult<I, String, E>
        where
            I: Clone
                + PartialEq
                + Slice<RangeFrom<usize>>
                + InputIter<Item = u8>
                + InputLength
                + InputTake
                + Compare<&'static [u8]>,
            E: ParseError<I>,
        {
            cond_if(
                meta.encoding == "UTF-8",
                map(many_till(le_u8, tag(U8NULL)), |(v, _)| {
                    String::from_utf8(v).unwrap_or_default()
                }),
                map(many_till(le_u16, tag(U16NULL)), |(v, _)| {
                    String::from_utf16(&v).unwrap_or_default()
                }),
            )
        }

        fn key_block<'a>(in_: &'a [u8], meta: &DictMeta) -> NomResult<&'a [u8], KeyMap> {
            let (in_, header) = map(
                tuple((
                    mdx_number(meta),
                    mdx_number(meta),
                    cond(meta.is_ver2(), be_u64),
                    mdx_number(meta),
                    mdx_number(meta),
                    cond(meta.is_ver2(), le_u32),
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

            let (mut in_, infos) = key_block_info(in_, &header, meta)?;

            fn key_entry<I, E>(meta: &DictMeta) -> impl Parser<I, (u64, String), E>
            where
                I: Clone
                    + Slice<RangeFrom<usize>>
                    + InputIter<Item = u8>
                    + InputLength
                    + PartialEq
                    + InputTake
                    + Compare<&'static [u8]>,
                E: ParseError<I>,
            {
                tuple((mdx_number(meta), mdx_string(meta)))
            }

            let mut keymap = KeyMap::new();

            for item in infos {
                let (i_, data) = content_block(in_, item.nb_compressed, item.nb_decompressed)?;
                in_ = i_;

                let (_, entries) =
                    count(key_entry(meta), item.n_entries as usize)(data.as_bytes())?;

                entries.iter().for_each(|entry| {
                    keymap.insert(entry.1.clone(), entry.0);
                })
            }

            Ok((in_, keymap))
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

        fn key_block_info<'a>(
            in_: &'a [u8],
            header: &KeyBlockHeader,
            meta: &DictMeta,
        ) -> NomResult<&'a [u8], Vec<KeyBlockInfo>> {
            fn unzip(in_: &[u8], checksum: u32) -> NomResult<&[u8], Vec<u8>> {
                nom_return!(in_, Vec<u8>, {
                    let key: Vec<u8>;
                    {
                        let mut vec = Vec::with_capacity(8);
                        vec.write_u32::<LittleEndian>(checksum)?;
                        vec.write_u32::<LittleEndian>(0x3695)?;

                        let mut hasher = Ripemd128::new();
                        hasher.input(vec);
                        key = hasher.result().to_vec();
                    }

                    let mut prev = 0x36;
                    let in_ = in_
                        .iter()
                        .enumerate()
                        .map(|(i, b)| {
                            let mut t = (*b >> 4 | *b << 4) & 0xff;
                            t = t ^ prev ^ (i & 0xff) as u8 ^ key[i % key.len()];

                            prev = *b;
                            t
                        })
                        .collect::<Vec<u8>>();

                    let mut output = Vec::new();

                    {
                        let mut decoder = ZlibDecoder::new(Cursor::new(in_));
                        decoder.read_to_end(&mut output)?;
                    }

                    output
                })
            }

            fn info_normal<'a>(
                in_: &'a [u8],
                header: &KeyBlockHeader,
                meta: &DictMeta,
            ) -> NomResult<&'a [u8], Vec<KeyBlockInfo>> {
                fn info_key<I, E>(meta: &DictMeta) -> impl FnMut(I) -> IResult<I, String, E>
                where
                    I: Clone + Slice<RangeFrom<usize>> + InputIter<Item = u8> + InputLength,
                    E: ParseError<I>,
                {
                    let is_ver2 = meta.is_ver2();
                    let is_utf8 = meta.encoding == "UTF-8";

                    fn key_bytes<I, O, E, F>(is_ver2: bool, f: F) -> impl Parser<I, Vec<O>, E>
                    where
                        I: Clone + Slice<RangeFrom<usize>> + InputIter<Item = u8> + InputLength,
                        F: Parser<I, O, E>,
                        E: ParseError<I>,
                    {
                        map(
                            length_count(
                                map(
                                    cond_if(is_ver2, be_u16, map(be_u8, |v| v as u16)),
                                    move |v| {
                                        if is_ver2 {
                                            v + 1
                                        } else {
                                            v
                                        }
                                    },
                                ),
                                f,
                            ),
                            move |mut v| {
                                if is_ver2 {
                                    v.truncate(v.len() - 1);
                                }
                                v
                            },
                        )
                    }

                    cond_if(
                        is_utf8,
                        map(key_bytes(is_ver2, le_u8), |v| {
                            String::from_utf8(v).unwrap_or_default()
                        }),
                        map(key_bytes(is_ver2, le_u16), |v| {
                            String::from_utf16(&v).unwrap_or_default()
                        }),
                    )
                }

                let (in_, infos) = count(
                    map(
                        tuple((
                            mdx_number(meta),
                            info_key(meta),
                            info_key(meta),
                            mdx_number(meta),
                            mdx_number(meta),
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
                            // 不包含 type 和 checksum
                            nb_compressed: nb_compressed - 8,
                            nb_decompressed,
                        },
                    ),
                    header.n_blocks as usize,
                )(in_)?;

                Ok((in_, infos))
            }

            let (in_, infos) = if meta.is_ver2() {
                let (in_, (_, checksum, data)) = tuple((
                    le_u32,
                    le_u32,
                    count(le_u8, header.nb_block_info as usize - 8),
                ))(in_)?;

                let (_, input) = unzip(&data, checksum)?;

                let (_, infos) = info_normal(&input, header, meta)?;
                (in_, infos)
            } else {
                info_normal(in_, header, meta)?
            };

            infos.iter().for_each(|info| println!("{:?}", info));

            Ok((in_, infos))
        }

        #[derive(Debug)]
        enum ContentBlockType {
            UnCompressed = 0,
            LZO = 1,
            Zlib = 2,
        }

        #[derive(Debug)]
        struct ContentBlock {
            block_type: ContentBlockType,
            checksum: u32,
            data: Vec<u8>,
        }

        fn content_block(
            in_: &[u8],
            nb_compressed: u64,
            nb_decompressed: u64,
        ) -> NomResult<&[u8], Vec<u8>> {
            let (in_, block) = map(
                tuple((
                    map(le_u32, |v| -> ContentBlockType {
                        match v {
                            0 => ContentBlockType::UnCompressed,
                            1 => ContentBlockType::LZO,
                            2 => ContentBlockType::Zlib,
                            _ => panic!("{} Unknown ContentBlockType", v),
                        }
                    }),
                    le_u32,
                    count(le_u8, nb_compressed as usize),
                )),
                |(block_type, checksum, data)| ContentBlock {
                    block_type,
                    checksum,
                    data,
                },
            )(in_)?;

            nom_return!(in_, Vec<u8>, {
                match block.block_type {
                    ContentBlockType::Zlib => {
                        let mut output = Vec::with_capacity(nb_decompressed as usize);
                        let mut decoder = ZlibDecoder::new(Cursor::new(block.data));
                        decoder.read_to_end(&mut output)?;
                        output
                    }
                    ContentBlockType::UnCompressed => block.data,
                    ContentBlockType::LZO => {
                        let lzo = minilzo_rs::LZO::init()?;

                        lzo.decompress(&block.data, nb_decompressed as usize)?
                    }
                }
            })
        }

        pub fn parse(in_: &[u8]) -> NomResult<&[u8], Mdx> {
            let (in_, dict_meta) = dict_meta(in_)?;
            let (in_, keymap) = key_block(in_, &dict_meta)?;

            nom_return!(in_, Mdx, Mdx { dict_meta, keymap })
        }
    }
}

fn main() {
    let dict_path = env::args().nth(1).unwrap();
    let mut file = File::open(dict_path).unwrap();
    let mut buf = Vec::new();
    file.read_to_end(&mut buf).unwrap();

    let dict = mdict::mdx::parse(&buf).unwrap().1;
    println!("{:?}", dict.keymap.iter().take(4).collect::<Vec<_>>());

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
