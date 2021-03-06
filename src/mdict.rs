use binread::io::Cursor;
use binread::{prelude::*, NullString, NullWideString, ReadOptions};
use byteorder::{LittleEndian, WriteBytesExt};
use flate2::read::ZlibDecoder;
use ripemd128::{Digest, Ripemd128};
use serde::Deserialize;
use std::collections::HashMap;
use std::fs::File;
use std::io::SeekFrom;
use std::io::{self, prelude::*};
use std::path::Path;
use std::u32;
use std::usize;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("{0}")]
    IO(#[from] io::Error),
    #[error("{0}")]
    BinRead(#[from] binread::Error),
    #[error("{0}")]
    De(#[from] quick_xml::DeError),
}

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, BinRead)]
pub struct Mdx {
    #[br(big)]
    n_dict_meta: u32,
    #[br(little, try_map(|data: NullWideString| parse_dict_meta(data)))]
    dict: DictMeta,
    #[br(little)]
    checksum: u32,

    key_block: MdxKeyBlock,
    record_block: MdxRecordBlock,
}

fn parse_dict_meta(data: NullWideString) -> Result<DictMeta> {
    let dict = quick_xml::de::from_str::<DictMeta>(&data.to_string())?;
    println!("{:?}", dict);
    Ok(dict)
}

impl Mdx {
    pub fn search(&self, text: String) -> Vec<(String, String)> {
        self.key_block
            .entries
            .iter()
            .filter(|item| item.0.contains(&text))
            .map(|item| (item.0.clone(), self.record_block.record(*item.1)))
            .collect::<_>()
    }
}

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

impl Mdx {
    pub fn parse(path: &Path) -> Result<Mdx> {
        let mut file = File::open(path)?;
        Ok(Mdx::read(&mut file)?)
    }
}

type KeyMap = HashMap<String, u64>;

#[derive(Debug, BinRead)]
struct MdxKeyBlock {
    #[br(big)]
    pub n_blocks: u64,
    #[br(big)]
    pub n_entires: u64,
    #[br(big)]
    pub nb_decompressed: u64,
    #[br(big)]
    pub nb_info: u64,
    #[br(big)]
    pub nb_blocks: u64,
    #[br(little)]
    pub checksum: u32,

    #[br(args(nb_info, n_blocks))]
    info: MdxKeyBlockInfo,
    #[br(count(n_blocks))]
    #[br(parse_with = |reader: &mut R, _: &ReadOptions, _: ()| -> BinResult<KeyMap> { parse_key_entries(reader, &info) })]
    entries: KeyMap,
}

#[derive(Debug, BinRead)]
#[br(import(nb_info: u64, n_blocks: u64))]
#[br(magic = 0x2u32)]
struct MdxKeyBlockInfo {
    #[br(little)]
    checksum: u32,
    #[br(count(nb_info - 8), try_map = |data: Vec<u8>| parse_key_block_info(data, n_blocks, checksum))]
    data: Vec<MdxKeyBlockInfoItem>,
}

#[derive(Debug)]
struct MdxKeyBlockInfoItem {
    n_entries: u64,
    nb_compressed: u64,
    nb_decompressed: u64,
}

fn parse_key_block_info(
    mut input: Vec<u8>,
    n_blocks: u64,
    checksum: u32,
) -> Result<Vec<MdxKeyBlockInfoItem>> {
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
    input.iter_mut().enumerate().for_each(|(i, b)| {
        let mut t = (*b >> 4 | *b << 4) & 0xff;
        t = t ^ prev ^ (i & 0xff) as u8 ^ key[i % key.len()];

        prev = *b;
        *b = t;
    });

    let mut data = Vec::new();
    {
        let mut decoder = ZlibDecoder::new(Cursor::new(input));
        decoder.read_to_end(&mut data)?;
    }

    let mut cursor = Cursor::new(&data);

    let mut vec: Vec<MdxKeyBlockInfoItem> = Vec::with_capacity(n_blocks as usize);

    for _ in 0..n_blocks {
        let n_entries: u64 = cursor.read_be()?;

        let head: u16 = cursor.read_be()?;
        cursor.seek(SeekFrom::Current((head + 1).into()))?;
        let tail: u16 = cursor.read_be()?;
        cursor.seek(SeekFrom::Current((tail + 1).into()))?;
        let nb_compressed = cursor.read_be::<u64>()?;
        let nb_decompressed = cursor.read_be::<u64>()?;

        vec.push(MdxKeyBlockInfoItem {
            n_entries,
            nb_compressed,
            nb_decompressed,
        });
    }

    Ok(vec)
}

#[derive(Debug, BinRead)]
#[br(little, repr = u32)]
enum ContentBlockType {
    UnCompressed = 0,
    LZO = 1,
    Zlib = 2,
}

#[derive(Debug, BinRead)]
#[br(import(nb_compressed: u64, nb_decompressed: u64))]
struct MdxContentBlock {
    block_type: ContentBlockType,
    #[br(little)]
    checksum: u32,
    #[br(parse_with = |reader: &mut R, _: &ReadOptions, _: ()| -> BinResult<Vec<u8>> { parse_content_block(reader, &block_type, nb_compressed - 8, nb_decompressed) })]
    data: Vec<u8>,
}

fn parse_content_block<R: Read + Seek>(
    reader: &mut R,
    _block_type: &ContentBlockType,
    nb_compressed: u64,
    nb_decompressed: u64,
) -> BinResult<Vec<u8>> {
    match _block_type {
        ContentBlockType::Zlib => {
            let mut block = Vec::with_capacity(nb_decompressed as usize);
            let mut decoder = ZlibDecoder::new(reader.take(nb_compressed));
            decoder.read_to_end(&mut block)?;
            Ok(block)
        }
        ContentBlockType::UnCompressed => todo!(),
        ContentBlockType::LZO => todo!(),
    }
}

#[derive(Debug, BinRead)]
struct MdxKeyItem {
    #[br(big)]
    id: u64,
    text: NullString,
}

fn parse_key_entries<R: Read + Seek>(reader: &mut R, info: &MdxKeyBlockInfo) -> BinResult<KeyMap> {
    let mut map = KeyMap::new();

    for item in &info.data {
        let block = MdxContentBlock::read_args(reader, (item.nb_compressed, item.nb_decompressed))?;

        {
            let mut reader = Cursor::new(block.data);

            for _ in 1..item.n_entries {
                let kv = MdxKeyItem::read(&mut reader)?;
                map.insert(kv.text.to_string(), kv.id);
            }
        }
    }

    Ok(map)
}

#[derive(Debug, BinRead)]
struct MdxRecordBlock {
    #[br(big)]
    n_blocks: u64,
    #[br(big)]
    n_entries: u64,
    #[br(big)]
    nb_info: u64,
    #[br(big)]
    nb_blocks: u64,
    #[br(big, count(n_blocks))]
    info: Vec<(u64, u64)>,
    #[br(parse_with = |reader: &mut R, _: &ReadOptions, _: ()| -> BinResult<Vec<MdxContentBlock>> { parse_record_entries(reader, &info) })]
    entries: Vec<MdxContentBlock>,
}

impl MdxRecordBlock {
    fn record(&self, mut pos: u64) -> String {
        std::str::from_utf8(
            &self
                .entries
                .iter()
                .find(|item| {
                    let len = item.data.len() as u64;
                    if pos > len {
                        pos -= len;
                        false
                    } else {
                        true
                    }
                })
                .map(|item| {
                    item.data
                        .iter()
                        .skip(pos as usize)
                        .take_while(|c| **c != 0)
                        .map(|c| *c)
                        .collect::<Vec<u8>>()
                })
                .unwrap(),
        )
        .map(|v| v.to_string())
        .unwrap_or_default()
    }
}

#[derive(Debug, BinRead)]
struct MdxRecordItem {
    text: NullString,
}

fn parse_record_entries<R: Read + Seek>(
    reader: &mut R,
    info: &Vec<(u64, u64)>,
) -> BinResult<Vec<MdxContentBlock>> {
    info.iter()
        .map(|item| MdxContentBlock::read_args(reader, *item))
        .collect::<_>()
}
