use binread::io::Cursor;
use binread::{prelude::*, NullString, NullWideString, ReadOptions};
use byteorder::{LittleEndian, WriteBytesExt};
use flate2::read::ZlibDecoder;
use quick_xml::de;
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
struct Mdx {
    #[br(big)]
    n_dict_meta: u32,
    #[br(little, try_map(|data: NullWideString| de::from_str::<DictMeta>(&data.to_string())))]
    pub dict: DictMeta,
    #[br(little)]
    checksum: u32,

    key_block: MdxKeyBlock,
    record_block: MdxRecordBlock,
}

#[derive(Debug, Deserialize, PartialEq)]
struct DictMeta {
    #[serde(rename = "GeneratedByEngineVersion")]
    pub generated_by_engine_version: f64,
    #[serde(rename = "RequiredEngineVersion")]
    pub required_engine_version: f64,
    #[serde(rename = "Format")]
    pub format: String,
    #[serde(rename = "KeyCaseSensitive")]
    pub key_case_sensitive: String,
    #[serde(rename = "StripKey")]
    pub strip_key: String,
    #[serde(rename = "Encrypted")]
    pub encrypted: usize,
    #[serde(rename = "RegisterBy")]
    pub register_by: String,
    #[serde(rename = "Description")]
    pub description: String,
    #[serde(rename = "Title")]
    pub title: String,
    #[serde(rename = "Encoding")]
    pub encoding: String,
    #[serde(rename = "CreationDate")]
    pub creation_date: String,
    #[serde(rename = "Compact")]
    pub compact: String,
    #[serde(rename = "Compat")]
    pub compat: String,
    #[serde(rename = "Left2Right")]
    pub left2right: String,
    #[serde(rename = "DataSourceFormat")]
    pub data_source_format: String,
    #[serde(rename = "StyleSheet")]
    pub style_sheet: String,
}

impl Mdx {
    fn parse(path: &Path) -> Result<Mdx> {
        let mut file = File::open(path)?;
        let v = Mdx::read(&mut file);
        Ok(v?)
    }
}

#[derive(Debug, BinRead)]
struct MdxKeyBlock {
    #[br(big)]
    n_blocks: u64,
    #[br(big)]
    n_entires: u64,
    #[br(big)]
    nb_decompressed: u64,
    #[br(big)]
    nb_info: u64,
    #[br(big)]
    nb_blocks: u64,
    #[br(little)]
    checksum: u32,

    #[br(args(nb_info, n_blocks))]
    info: MdxKeyBlockInfo,
    #[br(count(n_blocks))]
    #[br(parse_with = |reader: &mut R, _: &ReadOptions, _: ()| -> BinResult<HashMap<u64, String>> { parse_key_entries(reader, &info) })]
    entries: HashMap<u64, String>,
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

    let mut decoder = ZlibDecoder::new(Cursor::new(input));
    let mut data = Vec::new();
    decoder.read_to_end(&mut data)?;

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

    println!("num blocks: {:?}", n_blocks);

    Ok(vec)
}

#[derive(Debug, BinRead)]
enum ContentBlockType {
    #[br(magic = 0u32)]
    UnCompressed,
    #[br(magic = 1u32)]
    LZO,
    #[br(magic = 2u32)]
    Zlib,
}

#[derive(Debug, BinRead)]
#[br(import(nb_compressed: u64, nb_decompressed: u64))]
struct MdxContentBlock {
    block_type: ContentBlockType,
    #[br(little)]
    checksum: u32,
    #[br(count(nb_compressed - 8), try_map = |data: Vec<u8>| parse_key_block_item(data, &block_type, nb_decompressed))]
    data: Vec<u8>,
}

fn parse_key_block_item(
    input: Vec<u8>,
    block_type: &ContentBlockType,
    nb_decompressed: u64,
) -> Result<Vec<u8>> {
    println!("block_type: {:?}", block_type);
    // TODO: block_type zlib
    let mut block = Vec::with_capacity(nb_decompressed as usize);
    {
        let mut decoder = ZlibDecoder::new(Cursor::new(input));
        decoder.read_to_end(&mut block)?;
    }
    Ok(block)
}

#[derive(Debug, BinRead)]
struct MdxKeyItem {
    #[br(big)]
    id: u64,
    text: NullString,
}

fn parse_key_entries<R: Read + Seek>(
    reader: &mut R,
    info: &MdxKeyBlockInfo,
) -> BinResult<HashMap<u64, String>> {
    let mut map = HashMap::new();
    for item in &info.data {
        println!("info item: {:?}", item);
        let block = MdxContentBlock::read_args(reader, (item.nb_compressed, item.nb_decompressed))?;

        let mut reader = Cursor::new(block.data);

        for _ in 1..item.n_entries {
            let kv = MdxKeyItem::read(&mut reader)?;
            map.insert(kv.id, kv.text.to_string());
        }
    }

    println!("key_block entry num: {:?}", map.len());
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

#[derive(Debug, BinRead)]
struct MdxRecordItem {
    text: NullString,
}

fn parse_record_entries<R: Read + Seek>(
    reader: &mut R,
    info: &Vec<(u64, u64)>,
) -> BinResult<Vec<MdxContentBlock>> {
    println!("record block len: {:?}", info.len());
    info.iter()
        .map(|item| MdxContentBlock::read_args(reader, *item))
        .collect::<_>()
}

fn main() {
    let mdx = Mdx::parse(Path::new("剑桥双解.mdx")).unwrap();
}
