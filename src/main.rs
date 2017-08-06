use std::fs;
use std::fs::File;
use std::io::SeekFrom;
use std::io::Seek;
use std::io::Read;
use std::io::Write;
use std::io::Take;
use std::io::Error;
use std::io::ErrorKind;
use std::collections::HashMap;
use std::env;
use std::cmp;
use std::path::Path;

fn advance_magic(magic: &mut u32) -> u32 {
    let old = *magic;
    *magic = magic.wrapping_mul(7) + 3;
    return old;
}

fn ru32(stream: &mut File, result: &mut u32) -> bool {
    let mut buff = [0; 4];
    if let Err(_) = stream.read_exact(&mut buff) {
        return false;
    }

    *result = (((buff[0] as u32) << 0x00) & 0x000000FF) |
              (((buff[1] as u32) << 0x08) & 0x0000FF00) |
              (((buff[2] as u32) << 0x10) & 0x00FF0000) |
              (((buff[3] as u32) << 0x18) & 0xFF000000) ;

    return true;
}

#[derive(Clone, Copy)]
struct EntryData {
    offset: u32,
    magic: u32,
    size: u32,
}

struct Entry {
    offset: u32,
    magic: u32,
    stream: Take<File>,
}

impl Entry {
    fn read(&mut self, buf: &mut [u8]) -> usize {
        let mut maski = self.offset % 4;
        let mut offset = 0;
        let count = self.stream.read(buf).unwrap();
        let pre = ((4 - maski) % 4) as usize;

        self.offset += count as u32;

        for _ in 0..cmp::min(pre, count) {
            buf[offset] ^= ((self.magic >> (maski * 8)) & 0xff) as u8;
            maski += 1; offset += 1;
            if maski % 4 == 0 {
                advance_magic(&mut self.magic);
                maski = 0;
            }
        }

        if maski != 0 { return count; }

        for _ in 0..((count - pre)/4) {
            buf[offset + 0] ^= (self.magic & 0xff) as u8;
            buf[offset + 1] ^= ((self.magic >> 8) & 0xff) as u8;
            buf[offset + 2] ^= ((self.magic >> 16) & 0xff) as u8;
            buf[offset + 3] ^= ((self.magic >> 24) & 0xff) as u8;
            offset += 4;
            advance_magic(&mut self.magic);
        }

        for _ in 0..(count%4) {
            buf[offset] ^= ((self.magic >> (maski * 8)) & 0xff) as u8;
            maski += 1; offset += 1;
            if maski % 4 == 0 {
                advance_magic(&mut self.magic);
                maski = 0;
            }
        }

        return count;
    }
}

struct RGSSArchive {
    entry: HashMap<String, EntryData>,
    stream: File,
}

impl RGSSArchive {
    fn open(location: &str) -> Result<RGSSArchive, Error> {
        let mut stream = File::open(location)?;

        let mut header = [0u8; 8];
        stream.read_exact(&mut header)?;

        match String::from_utf8(header[..6].to_vec()) {
            Ok(header) => {
                if header != "RGSSAD" {
                }
            },
            Err(_) => return Err(Error::new(ErrorKind::InvalidData, "File header mismatch."))
        }

        // Check rgssad file version.
        if header[7] < 3 { RGSSArchive::open_rgssad(stream) } else { RGSSArchive::open_rgss3a(stream) }
    }

    fn open_rgssad(mut stream: File) -> Result<RGSSArchive, Error> {
        let mut magic = 0xDEADCAFEu32;
        let mut entry = HashMap::new();

        loop {
            let mut name_len: u32 = 0;
            let resp = ru32(&mut stream, &mut name_len);
            if !resp { break }
            name_len ^= advance_magic(&mut magic);

            let mut name_buf = vec![0u8; name_len as usize];
            stream.read_exact(&mut name_buf)?;
            for i in 0..(name_len as usize) {
                name_buf[i] ^= (advance_magic(&mut magic) & 0xff) as u8;
                if name_buf[i] == '\\' as u8 { name_buf[i] = '/' as u8 }
            }
            let name_buf = String::from_utf8(name_buf).unwrap();

            let mut data = EntryData { size: 0, offset: 0, magic: 0 };
            ru32(&mut stream, &mut data.size);
            data.size ^= advance_magic(&mut magic);
            data.offset = stream.seek(SeekFrom::Current(0))? as u32;
            data.magic = magic;

            stream.seek(SeekFrom::Current(data.size as i64))?;
            entry.insert(name_buf, data);
        }

        stream.seek(SeekFrom::Start(0))?;
        return Ok(RGSSArchive { entry: entry, stream: stream });
    }

    fn open_rgss3a(mut stream: File) -> Result<RGSSArchive, Error> {
        let mut magic = 0u32;
        let mut entry = HashMap::new();

        ru32(&mut stream, &mut magic);
        magic = magic * 9 + 3;

        loop {
            let mut offset: u32 = 0;
            let mut size: u32 = 0;
            let mut start_magic: u32 = 0;
            let mut name_len: u32 = 0;

            let resp = ru32(&mut stream, &mut offset);
            if !resp { break }
            offset ^= magic;

            if offset == 0 { break }

            let resp = ru32(&mut stream, &mut size);
            if !resp { break }
            size ^= magic;

            let resp = ru32(&mut stream, &mut start_magic);
            if !resp { break }
            start_magic ^= magic;

            let resp = ru32(&mut stream, &mut name_len);
            if !resp { break }
            name_len ^= magic;

            let mut name_buf = vec![0u8; name_len as usize];
            stream.read_exact(&mut name_buf)?;
            for i in 0..(name_len as usize) {
                name_buf[i] ^= ((magic >> 8*(i%4)) & 0xff) as u8;
                if name_buf[i] == '\\' as u8 { name_buf[i] = '/' as u8 }
            }
            let name_buf = String::from_utf8(name_buf).unwrap();

            let data = EntryData {
                size: size, offset: offset, magic: start_magic
            };

            entry.insert(name_buf, data);
        }

        stream.seek(SeekFrom::Start(0))?;
        return Ok(RGSSArchive { entry: entry, stream: stream });
    }

    fn read_entry(&self, key: &str) -> Option<Entry> {
        match self.entry.get(key) {
            Some(entry) => {
                let mut stream = self.stream.try_clone().unwrap();
                stream.seek(SeekFrom::Start(entry.offset as u64)).unwrap();
                Some(Entry {
                    offset: 0,
                    magic: entry.magic,
                    stream: stream.take(entry.size as u64),
                })
            }
            None => None
        }
    }
}

fn usage() {
    println!("Extract rgssad/rgss2a/rgss3a files.");
    println!("Commands:");
    println!("\tlist\t<filename>");
    println!("\tsave\t<filename> <location>");
}

fn create(location: String) -> File {
    let path = Path::new(location.as_str());
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    return File::create(path.to_str().unwrap()).unwrap();
}

fn main() {
    let args: Vec<String> = env::args().collect();
    match args.len() {
        1...2 => usage(),
        3 => {
            if args[1] != "list" { usage(); return; }
            match RGSSArchive::open(args[2].as_str()) {
                Ok(archive) => {
                    for (name, data) in &archive.entry {
                        println!("{}: EntryData {{ size: {}, offset: {}, magic: {} }}", name, data.size, data.offset, data.magic);
                    }
                },
                Err(err) => println!("FAILED: {}", err.to_string())
            }
        },
        4 => {
            if args[1] != "save" { usage(); return; }
            let archive = RGSSArchive::open(args[2].as_str());
            if let Err(err) = archive {
                println!("FAILED: {}", err.to_string()); return;
            }
            let archive = archive.unwrap();
            let entries = archive.entry.iter();

            let mut buf = [0u8; 1024];

            for (name, _) in entries {
                println!("Extracting: {}", name);
                let mut entry = archive.read_entry(name).unwrap();
                let mut file = create(args[3].clone() + &"/".to_string() + &name.to_string());
                loop {
                    let count = entry.read(&mut buf);
                    if count == 0 { break }
                    if count < 1024 {
                        file.write(&buf[..count]).unwrap();
                    } else {
                        file.write(&buf).unwrap();
                    }
                }
            }
        },
        _ => usage(),
    }
}
