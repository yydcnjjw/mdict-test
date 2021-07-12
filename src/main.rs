use binread::io::Cursor;
use binread::{prelude::*, NullWideString};
use byteorder::{LittleEndian, WriteBytesExt};
use flate2::read::ZlibDecoder;
use ripemd128::{Digest, Ripemd128};
use std::io::prelude::*;
use std::io::SeekFrom;
use std::u32;

use std::usize;

#[derive(Debug, BinRead)]
struct MdxHeader {
    #[br(big)]
    len: u32,
    #[br(little, count=len)]
    data: NullWideString,
    #[br(little)]
    checksum: u32,
}

#[derive(Debug, BinRead)]
struct MdxKeyBlockHeader {
    #[br(big)]
    num_bytes_block: u64,
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
}

#[derive(Debug, BinRead)]
struct MdxKeyBlockInfoHeader {
    #[br(big)]
    mark: u32,
    #[br(little)]
    checksum: u32,
}

#[derive(Debug, BinRead)]
struct MdxKeyBlockInfoItem {
    #[br(big)]
    n_entries: u64,
}

#[derive(Debug, BinRead)]
struct MdxKeyBlock {
    #[br(little)]
    block_type: u32,
    #[br(little)]
    checksum: u32,
}

fn main() {
    let mut cursor = Cursor::new(include_bytes!(
        "/home/yydcnjjw/Downloads/字典包/剑桥双解.mdx"
    ));

    let header = MdxHeader::read(&mut cursor).unwrap();
    println!("{:?}", header);
    println!("position {:?}", cursor.position());

    let block = MdxKeyBlockHeader::read(&mut cursor).unwrap();
    println!("{:?}", block);
    println!("position {:?}", cursor.position());

    let info = MdxKeyBlockInfoHeader::read(&mut cursor).unwrap();
    println!("{:?}", info);
    println!("position {:?}", cursor.position());

    let mut buf: Vec<u8> = vec![0; (block.num_bytes_info - 8) as usize];
    cursor.read(&mut buf).unwrap();
    println!("position {:?}", cursor.position());

    let key: Vec<u8>;
    {
        let mut vec = Vec::with_capacity(8);
        vec.write_u32::<LittleEndian>(info.checksum).unwrap();
        vec.write_u32::<LittleEndian>(0x3695).unwrap();

        let mut hasher = Ripemd128::new();
        hasher.input(vec);
        key = hasher.result().to_vec();
    }

    let mut prev = 0x36;
    buf.iter_mut().enumerate().for_each(|(i, b)| {
        let mut t = (*b >> 4 | *b << 4) & 0xff;
        t = t ^ prev ^ (i & 0xff) as u8 ^ key[i % key.len()];

        prev = *b;
        *b = t;
    });

    let mut decoder = ZlibDecoder::new(&buf[..]);
    let mut info = Vec::new();
    decoder.read_to_end(&mut info).unwrap();
    {
        let mut cursor = Cursor::new(&info);

        let item = MdxKeyBlockInfoItem::read(&mut cursor).unwrap();
        let head: u16 = cursor.read_be().unwrap();
        cursor.seek(SeekFrom::Current((head + 1).into())).unwrap();
        let tail: u16 = cursor.read_be().unwrap();
        cursor.seek(SeekFrom::Current((tail + 1).into())).unwrap();
        let compressed_size = cursor.read_be::<u64>().unwrap();
        let decompressed_size = cursor.read_be::<u64>().unwrap();
        println!("{}, {}", compressed_size, decompressed_size);
        println!("{:?}", item);
    }
    // println!("{:02x?}", info);

    let key_block = MdxKeyBlock::read(&mut cursor).unwrap();
    println!("{:02x?}", key_block);
    println!("position {:?}", cursor.position());

    {
        let mut decoder = ZlibDecoder::new(cursor);
        let mut block = Vec::new();
        decoder.read_to_end(&mut block).unwrap();
        // println!("{:02x?}", block);
        let mut cursor = Cursor::new(block);
        let id = cursor.read_be::<u64>().unwrap();
        let mut text = String::new();
        unsafe {
            cursor.read_until(0, text.as_mut_vec()).unwrap();
        }

        let id = cursor.read_be::<u64>().unwrap();
        let mut text = String::new();
        unsafe {
            cursor.read_until(0, text.as_mut_vec()).unwrap();
        }

        let id = cursor.read_be::<u64>().unwrap();
        let mut text = String::new();
        unsafe {
            cursor.read_until(0, text.as_mut_vec()).unwrap();
        }

        println!("{}", id);
        println!("{}", text);
    }
}
