#![allow(unused)]

use crc32_v2::byfour::crc32_little;
use std::env;
use std::fs::File;
use std::io::{copy, Error, ErrorKind, Read, Seek, SeekFrom, Write};
use std::mem;
use std::str;
use std::str::FromStr;

const CRC32_INIT: u32 = 0;

#[derive(Debug, Clone)]
struct Header {
    header: u64,
}

#[derive(Debug, Clone)]
struct Chunk {
    size: u32,
    r#type: u32,
    data: Vec<u8>,
    crc: u32,
}

#[derive(Debug, Clone)]
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
    fn pre_process_image(file: &mut File) -> Result<MetaChunk, Error> {
        let mut header = Header { header: 0 };
        file.read_exact(unsafe { mem::transmute::<_, &mut [u8; 8]>(&mut header.header) })?;

        let b_arr = u64_to_u8_array(header.header);
        if &b_arr[1..4] != b"PNG" {
            panic!("Not a valid PNG format");
        } else {
            println!("It is a valid PNG file. Let's process it!");
        }

        let offset = file.stream_position()?;
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
            println!("Chunk offset: {:x}", offset);
            self.read_chunk(file);
            chunk_type = self.chunk_type_to_string();
            count += 1;
        }
    }

    fn get_offset<T: Read + Seek>(&mut self, file: &mut T) -> u64 {
        let offset = file.seek(SeekFrom::Current(5)).unwrap();
        self.offset = offset;
        offset
    }

    fn read_chunk<T: Read + Seek>(&mut self, file: &mut T) {
        self.read_chunk_size(file);
        self.read_chunk_type(file);
        self.read_chunk_bytes(file, self.chk.size);
        self.read_chunk_crc(file);
    }

    fn read_chunk_size<R: Read>(&mut self, file: &mut R) {
        let mut size_bytes = [0; 4];

        match file.read_exact(&mut size_bytes) {
            Ok(_) => {
                // Successfully read the expected number of bytes
                // self.chk.size = u32::from_be_bytes(size_bytes);
                // let max_number = *size_bytes.iter().max_by(|a, b| a.cmp(b)).unwrap();
                // self.chk.size = max_number as u32;
                self.chk.size = size_bytes[3] as u32;
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

    fn read_chunk_type<R: Read>(&mut self, file: &mut R) {
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

    fn read_chunk_bytes<T: Read + Seek>(&mut self, file: &mut T, len: u32) {
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
                    .truncate(file.stream_position().unwrap() as usize);
            }
            Err(err) => {
                eprintln!("Error reading chunk bytes: {}", err);
            }
        }
    }

    fn read_chunk_crc<R: Read>(&mut self, file: &mut R) {
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

    fn marshal_data(&self) -> Vec<u8> {
        let mut bytes_msb = Vec::new();
        bytes_msb.push(self.chk.data.len() as u8);
        bytes_msb.write_all(&self.chk.r#type.to_be_bytes()).unwrap();
        bytes_msb.write_all(&self.chk.data).unwrap();
        bytes_msb.write_all(&self.chk.crc.to_be_bytes()).unwrap();
        println!("Encoded Payload: {:?}", bytes_msb);
        bytes_msb
    }

    fn write_data<R: Read + Seek, W: Write>(&mut self, r: &mut R, c: &CmdArgs, mut w: W) {
        // Common encoding and decoding process
        let b_arr = u64_to_u8_array(self.header.header);
        w.write_all(&b_arr).unwrap();
        let offset = i64::from_str(&c.offset).unwrap();
        let mut buff = vec![0; (offset - 8) as usize];

        if c.encode {
            // Encoding specific operations
            buff.resize((offset - 8) as usize, 0);
            r.read_exact(&mut buff).unwrap();
            w.write_all(&buff).unwrap();
            let data: Vec<u8> = self.marshal_data();
            w.write_all(&data).unwrap();
            // Uncomment the following line to preserve the length of the image after manipulation
            // r.seek(SeekFrom::Current(data.len().try_into().unwrap())).expect("Error seeking to offset");
            copy(r, &mut w).unwrap();
        } else if c.decode {
            // Decoding specific operations
            buff.resize((offset - 16) as usize, 0);
            r.read_exact(&mut buff).unwrap();
            w.write_all(&buff).unwrap();
            let offset = self.get_offset(r);
            self.read_chunk(r);
            println!("Encoded Payload: {:?}", self.chk);
            let decoded_data = xor_encode_decode(&self.chk.data, &c.key);
            let decoded_string = String::from_utf8_lossy(&decoded_data);
            println!("Decoded Payload: {:?}", decoded_data);
            println!("Original Data: {:?}", decoded_string);
            r.seek(SeekFrom::Current(self.chk.data.len().try_into().unwrap()))
                .expect("Error seeking to offset");
            copy(r, &mut w).unwrap();
        }
    }
}

struct CmdArgs {
    input: String,
    output: String,
    meta: bool,
    suppress: bool,
    offset: String,
    inject: bool,
    payload: String,
    r#type: String,
    encode: bool,
    decode: bool,
    key: String,
}

impl CmdArgs {
    fn new(args: &[String]) -> Result<Self, &'static str> {
        if args.len() < 5 {
            return Err("Not enough arguments. Usage: program input output offset payload");
        }

        Ok(CmdArgs {
            input: args[1].clone(),
            output: args[2].clone(),
            meta: false,
            suppress: false,
            offset: args[3].clone(),
            inject: false,
            payload: args[4].clone(),
            r#type: String::from("PNG"),
            encode: args.contains(&String::from("encode")),
            decode: args.contains(&String::from("decode")),
            key: args[5].clone(),
        })
    }
}

fn xor_encode_decode(input: &[u8], key: &str) -> Vec<u8> {
    let mut b_arr = Vec::with_capacity(input.len());
    for (i, &byte) in input.iter().enumerate() {
        b_arr.push(byte ^ key.as_bytes()[i % key.len()]);
    }
    b_arr
}

fn main() {
    let args: Vec<String> = env::args().collect();

    let cmd_line_opts = match CmdArgs::new(&args) {
        Ok(opts) => opts,
        Err(err) => {
            eprintln!("Error: {}", err);
            return;
        }
    };

    let mut file = File::open(&cmd_line_opts.input).expect("Error opening file");

    let mut meta_chunk = MetaChunk::pre_process_image(&mut file).expect("Error processing image");

    if cmd_line_opts.encode {
        let mut file_writer = File::create(&cmd_line_opts.output).unwrap();
        // Assuming encoding is requested
        let encoded_data = xor_encode_decode(cmd_line_opts.payload.as_bytes(), &cmd_line_opts.key);
        println!("original bytes {:?}", cmd_line_opts.payload.as_bytes());

        // Calculate CRC for the encoded data
        let mut bytes_msb = Vec::new();
        bytes_msb
            .write_all(&meta_chunk.chk.r#type.to_be_bytes())
            .unwrap();
        bytes_msb.write_all(&encoded_data).unwrap();
        let crc = crc32_little(meta_chunk.chk.crc, &bytes_msb);

        // Update the MetaChunk with the encoded data and CRC
        meta_chunk.chk.data = encoded_data;
        meta_chunk.chk.crc = crc;

        // Create a new mutable reference to file_reader
        let mut file_reader = &file;

        meta_chunk.write_data(&mut file_reader, &cmd_line_opts, &mut file_writer);

        println!("Image encoded and written successfully!");
    } else if cmd_line_opts.decode {
        let mut file_writer = File::create(&cmd_line_opts.output).unwrap();
        let mut file_reader = &file;
        meta_chunk.write_data(&mut file_reader, &cmd_line_opts, &mut file_writer);
        // meta_chunk.process_image(&mut file);
    }
}
