use std::fs::File;
use std::io::ErrorKind;
use std::io::{Read, Seek, SeekFrom};
use std::mem;
use std::str;

#[derive(Debug)]
struct Header {
    header: u64,
}

#[derive(Debug)]
struct Chunk {
    size: u32,
    r#type: u32,
    data: Vec<u8>,
    crc: u32,
}

struct MetaChunk {
    header: Header,
    chk: Chunk,
    offset: u64,
}

fn u64_to_u8_array(value: u64) -> [u8; 8] {
    let bytes = value.to_ne_bytes();
    let mut result = [0; 8];

    unsafe {
        // Transmute the byte array into an array of unsigned 8-bit integers
        result = mem::transmute_copy(&bytes);
    }

    result
}

impl MetaChunk {
    fn pre_process_image(file: &mut File) -> Result<MetaChunk, std::io::Error> {
        let mut header = Header { header: 0 };
        file.read_exact(unsafe { mem::transmute::<_, &mut [u8; 8]>(&mut header.header) })?;

        let b_arr = u64_to_u8_array(header.header);
        if &b_arr[1..4] != b"PNG" {
            panic!("Not a valid PNG format");
        } else {
            println!("It is a valid PNG file. Let's process it!");
        }

        let offset = file.seek(SeekFrom::Current(0))?;
        Ok(MetaChunk {
            header,
            chk: Chunk {
                size: 0,
                r#type: 0,
                data: Vec::new(),
                crc: 0,
            },
            offset,
        })
    }

    fn process_image(&mut self, file: &mut File) {
        let mut count = 1;
        let mut chunk_type = String::new();
        let end_chunk_type = "IEND";

        while chunk_type != end_chunk_type {
            println!("---- Chunk # {} ----", count);
            let offset = self.get_offset(file);
            println!("Chunk Offset: {:x}", offset);
            self.read_chunk(file);
            chunk_type = self.chunk_type_to_string();
            count += 1;
        }
    }

    fn get_offset(&mut self, file: &mut File) -> u64 {
        let offset = file.seek(SeekFrom::Current(0)).unwrap();
        self.offset = offset;
        offset
    }

    fn read_chunk(&mut self, file: &mut File) {
        self.read_chunk_size(file);
        self.read_chunk_type(file);
        self.read_chunk_bytes(file, self.chk.size);
        self.read_chunk_crc(file);
    }

    fn read_chunk_size(&mut self, file: &mut File) {
        let mut size_bytes = [0; 4];

        match file.read_exact(&mut size_bytes) {
            Ok(_) => {
                // Successfully read the expected number of bytes
                self.chk.size = u32::from_be_bytes(size_bytes);
            }
            Err(err) if err.kind() == ErrorKind::UnexpectedEof => {
                // Handle the situation where the file ends before reading the expected bytes
                eprintln!("Warning: Reached end of file prematurely while reading chunk size");
            }
            Err(err) => {
                eprintln!("Error reading chunk size bytes: {}", err);
            }
        }
    }

    fn read_chunk_type(&mut self, file: &mut File) {
        let mut type_bytes = [0; 4];

        match file.read_exact(&mut type_bytes) {
            Ok(_) => {
                // Successfully read the expected number of bytes
                self.chk.r#type = u32::from_be_bytes(type_bytes);
            }
            Err(err) if err.kind() == ErrorKind::UnexpectedEof => {
                // Handle the situation where the file ends before reading the expected bytes
                eprintln!("Warning: Reached end of file prematurely while reading chunk type");
            }
            Err(err) => {
                eprintln!("Error reading chunk type bytes: {}", err);
            }
        }
    }

    fn read_chunk_bytes(&mut self, file: &mut File, len: u32) {
        self.chk.data = vec![0; len as usize];

        match file.read_exact(&mut self.chk.data) {
            Ok(_) => {
                // Successfully read the expected number of bytes
            }
            Err(err) if err.kind() == ErrorKind::UnexpectedEof => {
                eprintln!("Error reading chunk bytes: Reached end of file prematurely");
                // Update the length of the Chunk based on the actual number of bytes read
                self.chk
                    .data
                    .truncate(file.seek(SeekFrom::Current(0)).unwrap() as usize);
            }
            Err(err) => {
                eprintln!("Error reading chunk bytes: {}", err);
            }
        }
    }

    fn read_chunk_crc(&mut self, file: &mut File) {
        let mut crc_bytes = [0; 4];

        match file.read_exact(&mut crc_bytes) {
            Ok(_) => {
                // Successfully read the expected number of bytes
                self.chk.crc = u32::from_be_bytes(crc_bytes);
            }
            Err(err) if err.kind() == ErrorKind::UnexpectedEof => {
                // Handle the situation where the file ends before reading the expected bytes
                eprintln!("Warning: Reached end of file prematurely while reading CRC");
            }
            Err(err) => {
                eprintln!("Error reading CRC bytes: {}", err);
            }
        }
    }

    fn chunk_type_to_string(&self) -> String {
        String::from_utf8_lossy(&self.chk.r#type.to_be_bytes()).to_string()
    }
}

fn main() {
    let mut file = File::open("prj.png").expect("Error opening file");

    let mut meta_chunk = MetaChunk::pre_process_image(&mut file).expect("Error processing image");

    meta_chunk.process_image(&mut file);
}
