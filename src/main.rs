use html2text::from_read;
use mdict_test::mdict;
use std::{io::Cursor, path::Path};

fn main() {
    let dict = std::env::args().nth(1).unwrap();
    let mdx = mdict::Mdx::parse(Path::new(&dict));

    match mdx {
        Ok(mdx) => {
            let query = std::env::args().nth(2).unwrap();
            println!("query: {}", query);
            mdx.search(query)
                .iter()
                .map(|item| (item.0.clone(), from_read(Cursor::new(&item.1), 100)))
                .for_each(|item| {
                    println!("{}", item.1);
                })
        }
        Err(e) => println!("{:?}", e),
    }
}
