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
use std::usize;
use std::{u32};
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
    meta_size: u32,
    #[br(little, count(meta_size), try_map(|data: NullWideString| de::from_str::<Dictionary>(&data.to_string())))]
    pub dict: Dictionary,
    #[br(little)]
    checksum: u32,

    key_block: MdxKeyBlock,
}

#[derive(Debug, Deserialize, PartialEq)]
struct Dictionary {
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
        println!("read pos: {:?}", file.seek(SeekFrom::Current(0))?);
        Ok(v?)
    }
}

#[derive(Debug, BinRead)]
struct MdxKeyBlock {
    #[br(big)]
    num_blocks: u64,
    #[br(big)]
    n_entires: u64,
    #[br(big)]
    num_bytes_decompressed: u64,
    #[br(big)]
    num_bytes_info: u64,
    #[br(big)]
    num_bytes_blocks: u64,
    #[br(little)]
    checksum: u32,

    #[br(args(num_bytes_info, num_blocks))]
    info: MdxKeyBlockInfo,
    #[br(count(num_blocks))]
    blocks: Vec<MdxKeyBlockItem>,
}

fn decode_key_block_info(
    mut input: Vec<u8>,
    num_blocks: u64,
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

    let mut vec: Vec<MdxKeyBlockInfoItem> = Vec::with_capacity(num_blocks as usize);

    for _ in 0..num_blocks {
        let n_entries: u64 = cursor.read_be()?;

        let head: u16 = cursor.read_be()?;
        cursor.seek(SeekFrom::Current((head + 1).into()))?;
        let tail: u16 = cursor.read_be()?;
        cursor.seek(SeekFrom::Current((tail + 1).into()))?;
        let compressed_size = cursor.read_be::<u64>()?;
        let decompressed_size = cursor.read_be::<u64>()?;

        vec.push(MdxKeyBlockInfoItem {
            n_entries,
            compressed_size,
            decompressed_size,
        });
    }

    println!("num blocks: {:?}", num_blocks);
    println!("{:?}", vec);

    Ok(vec)
}

#[derive(Debug, BinRead)]
#[br(import(num_bytes_info: u64, num_blocks: u64))]
#[br(magic = 0x2u32)]
struct MdxKeyBlockInfo {
    #[br(little)]
    checksum: u32,
    #[br(count(num_bytes_info - 8), try_map = |data: Vec<u8>| decode_key_block_info(data, num_blocks, checksum))]
    data: Vec<MdxKeyBlockInfoItem>,
}

#[derive(Debug)]
struct MdxKeyBlockInfoItem {
    n_entries: u64,
    compressed_size: u64,
    decompressed_size: u64,
}

#[derive(Debug, BinRead)]
enum KeyBlockType {
    #[br(magic = 0u32)]
    UnCompressed,
    #[br(magic = 1u32)]
    LZO,
    #[br(magic = 2u32)]
    Zlib,
}

#[derive(Debug, BinRead)]
struct MdxKeyBlockItem {
    block_type: KeyBlockType,
    #[br(little)]
    checksum: u32,
    #[br(parse_with = |reader: &mut R, _: &ReadOptions, _: ()| -> BinResult<HashMap<u64, String>> { parse_key_item(reader, &block_type) })]
    data: HashMap<u64, String>,
}

#[derive(Debug, BinRead)]
struct MdxKeyItem {
    #[br(big)]
    id: u64,
    text: NullString,
}

fn parse_key_item<R: Read + Seek>(
    reader: &mut R,
    block_type: &KeyBlockType,
) -> BinResult<HashMap<u64, String>> {
    println!("block_type: {:?}", block_type);

    let mut block = Vec::new();
    {
        let mut decoder = ZlibDecoder::new(reader);
        decoder.read_to_end(&mut block)?;
    }

    let mut map = HashMap::new();
    {
        let mut reader = Cursor::new(block);
        let len = reader.get_ref().len() as u64;

        while reader.position() < len {
            let item = reader.read_le::<MdxKeyItem>()?;
            map.insert(item.id, item.text.to_string());
        }
    }

    println!("key_block entry num: {:?}", map.len());
    Ok(map)
}

fn main() {
    let mdx = Mdx::parse(Path::new("/home/yydcnjjw/Downloads/字典包/剑桥双解.mdx")).unwrap();
    println!("{:?}", mdx);
}
