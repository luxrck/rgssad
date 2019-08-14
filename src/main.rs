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

extern crate regex;
use regex::Regex;

static __VERSION__: &str = "0.1.4";

// Errors
static E_INVALIDHDR: &str = "Input file header mismatch.";
static E_INVALIDVER: &str = "Not supported version.";
static E_INVALIDMGC: &str = "Magic number read failed.";
static E_INVALIDKEY: &str = "Key not found.";


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

fn wu32(stream: &mut File, data: &u32) -> bool {
    let mut buff = [0u8; 4];

    buff[0] = (data & 0x000000FF) as u8;
    buff[1] = ((data & 0x0000FF00) >> 0x08) as u8;
    buff[2] = ((data & 0x00FF0000) >> 0x10) as u8;
    buff[3] = ((data & 0xFF000000) >> 0x18) as u8;

    if let Err(_) = stream.write_all(&buff[..]) {
        return false;
    }

    return true;
}

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
    fn write(&mut self, buf: &Take<File>) {

    }

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

        unsafe {
            let len = (count - pre) / 4;
            let dat = buf[..len*4].as_mut_ptr() as *mut u32;

            for i in 0..(len as isize) {
                *dat.offset(i) = *dat.offset(i) ^ advance_magic(&mut self.magic);
            }

            offset += len * 4;
        }

        for i in 0..(count%4) {
            buf[offset + i] ^= ((self.magic >> (maski * 8)) & 0xff) as u8;
            maski += 1;
        }

        return count;
    }
}


struct RGSSArchive {
    magic: u32,
    version: u8,
    entry: HashMap<String, EntryData>,
    stream: File,
}

impl RGSSArchive {
    fn create(location: &str, version: u8) -> Result<Self, Error> {
        let mut stream = File::create(location)?;
        if version < 1 || version > 3 {
            return Err(Error::new(ErrorKind::InvalidData, E_INVALIDVER));
        }

        stream.write_all(&[b'R', b'G', b'S', b'S', b'A', b'D', version]);

        Ok(RGSSArchive { magic: if version == 3 { 0u32 } else { 0xDEADCAFEu32 }, version: version, entry: HashMap::<String, EntryData>::new(), stream: stream })
    }

    fn open(location: &str) -> Result<Self, Error> {
        let mut stream = File::open(location)?;

        let mut header = [0u8; 8];
        stream.read_exact(&mut header)?;

        match String::from_utf8(header[..6].to_vec()) {
            Ok(h) => {
                if h != "RGSSAD" {
                    return Err(Error::new(ErrorKind::InvalidData, E_INVALIDHDR));
                }
            },
            Err(_) => return Err(Error::new(ErrorKind::InvalidData, E_INVALIDHDR))
        }

        // Check rgssad file version.
        return match header[7] {
            1|2 => RGSSArchive::open_rgssad(stream, header[7]),
              3 => RGSSArchive::open_rgss3a(stream, header[7]),
              _ => Err(Error::new(ErrorKind::InvalidData, E_INVALIDVER)),
        }
    }

    fn open_rgssad(mut stream: File, version: u8) -> Result<Self, Error> {
        let mut magic = 0xDEADCAFEu32;
        let mut entry = HashMap::new();

        loop {
            let mut name_len: u32 = 0;
            if !ru32(&mut stream, &mut name_len) { break }
            name_len ^= advance_magic(&mut magic);

            let mut name_buf = vec![0u8; name_len as usize];
            stream.read_exact(&mut name_buf)?;
            for i in 0..(name_len as usize) {
                name_buf[i] ^= (advance_magic(&mut magic) & 0xff) as u8;
                if name_buf[i] == '\\' as u8 { name_buf[i] = '/' as u8 }
            }
            let name_buf = String::from_utf8(name_buf);
            if let Err(_) = name_buf { break }
            let name_buf = name_buf.unwrap();

            let mut data = EntryData { size: 0, offset: 0, magic: 0 };
            ru32(&mut stream, &mut data.size);
            data.size ^= advance_magic(&mut magic);
            data.offset = stream.seek(SeekFrom::Current(0))? as u32;
            data.magic = magic;

            stream.seek(SeekFrom::Current(data.size as i64))?;
            entry.insert(name_buf, data);
        }

        stream.seek(SeekFrom::Start(0))?;
        return Ok(RGSSArchive { magic: magic, version: version, entry: entry, stream: stream });
    }

    fn open_rgss3a(mut stream: File, version: u8) -> Result<Self, Error> {
        let mut magic = 0u32;
        let mut entry = HashMap::new();

        if !ru32(&mut stream, &mut magic) {
            return Err(Error::new(ErrorKind::InvalidData, E_INVALIDMGC));
        }
        magic = magic * 9 + 3;

        loop {
            let mut offset: u32 = 0;
            let mut size: u32 = 0;
            let mut start_magic: u32 = 0;
            let mut name_len: u32 = 0;

            if !ru32(&mut stream, &mut offset) { break };
            offset ^= magic;

            if offset == 0 { break }

            if !ru32(&mut stream, &mut size) { break }
            size ^= magic;

            if !ru32(&mut stream, &mut start_magic) { break}
            start_magic ^= magic;

            if !ru32(&mut stream, &mut name_len) { break }
            name_len ^= magic;

            let mut name_buf = vec![0u8; name_len as usize];
            stream.read_exact(&mut name_buf)?;
            for i in 0..(name_len as usize) {
                name_buf[i] ^= ((magic >> 8*(i%4)) & 0xff) as u8;
                if name_buf[i] == '\\' as u8 { name_buf[i] = '/' as u8 }
            }
            let name_buf = String::from_utf8(name_buf);
            if let Err(_) = name_buf { break }
            let name_buf = name_buf.unwrap();

            let data = EntryData {
                size: size, offset: offset, magic: start_magic
            };

            entry.insert(name_buf, data);
        }

        stream.seek(SeekFrom::Start(0))?;
        return Ok(RGSSArchive {magic: magic, version: version, entry: entry, stream: stream });
    }

    fn get_key(&self, key: &str) -> Result<Entry, Error> {
        match self.entry.get(key) {
            Some(entry) => {
                let mut stream = self.stream.try_clone()?;
                stream.seek(SeekFrom::Start(entry.offset as u64))?;
                Ok(Entry {
                    offset: 0,
                    magic: entry.magic,
                    stream: stream.take(entry.size as u64),
                })
            }
            None => Err(Error::new(ErrorKind::InvalidData, E_INVALIDKEY)),
        }
    }

    // fn put_key(&self, key: &str, stream: &mut File) -> Result<Entry, Error> {
    //     match self.version {
    //         1|2 => self.put_key_rgssad(stream),
    //           3 => self.put_key_rgss3a(stream),
    //     }
    // }
}


fn usage() {
    println!("Extract rgssad/rgss2a/rgss3a files.
Commands:
    help
    version
    list        <filename>
    unpack      <filename> <location> [<filter>]");
}

fn list(archive: RGSSArchive) {
    for (name, data) in archive.entry {
        println!("{}: EntryData {{ size: {}, offset: {}, magic: {} }}", name, data.size, data.offset, data.magic);
    }
}

fn pack(src: &str, out: &str, version: u8) {
    fn walkdir(archive: &mut RGSSArchive, d: &Path, r: &Path) {
        for entry in fs::read_dir(&d).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            if path.is_dir() {
                walkdir(archive, &path, r);
            } else {
                let key = path.strip_prefix(r).unwrap().to_str().unwrap();
                let mut stream = File::open(&path).unwrap();

                // TODO: implement this.
                //archive.put_key(key, stream);
            }
        }
    };

    let root = Path::new(src);
    if !root.is_dir() {
        println!("FAILED: source is not a directory."); return
    }

    let mut archive = match RGSSArchive::create(out, version) {
        Ok(x) => x,
        Err(e) => {
            println!("FAILED: unable to create output file. {}", e); return
        }
    };
    walkdir(&mut archive, root, root);
}

fn unpack(archive: RGSSArchive, dir: &str, filter: &str) {
    fn create(location: String) -> File {
        let path = Path::new(location.as_str());
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        return File::create(path.to_str().unwrap()).unwrap();
    }

    let entries = archive.entry.iter();
    let filter = match Regex::new(filter) {
        Ok(re) => re,
        Err(_) => {
            println!("FAILED: Invalid regex filter: {}", filter); return
        }
    };

    let mut buf = [0u8; 8192];

    for (name, _) in entries {
        if !filter.is_match(name) { continue }

        println!("Extracting: {}", name);
        let entry = archive.get_key(name);
        if let Err(err) = entry {
            println!("FAILED: read entry failed, {}", err.to_string()); return;
        }
        let mut entry = entry.unwrap();

        let mut file = create(dir.to_string() + &"/".to_string() + &name.to_string());
        loop {
            let count = entry.read(&mut buf);
            if count == 0 { break }
            if let Err(err) = file.write(&buf[..count]) {
                println!("FAILED: key save failed, {}", err.to_string()); return;
            }
        }
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 { usage(); return }
    match args[1].as_str() {
        "help" => usage(),
        "version" => {
            assert!(args.len() == 2);
            println!("version: {}", __VERSION__);
        },
        "list" => {
            assert!(args.len() == 3);
            let archive = RGSSArchive::open(args[2].as_str());
            if let Err(err) = archive {
                println!("FAILED: file parse failed, {}", err.to_string()); return;
            }
            let archive = archive.unwrap();

            list(archive);
        },
        "unpack" => {
            assert!(args.len() > 3 && args.len() < 6);
            let archive = RGSSArchive::open(args[2].as_str());
            if let Err(err) = archive {
                println!("FAILED: file parse failed, {}", err.to_string()); return;
            }
            let archive = archive.unwrap();
            unpack(archive, args[3].as_str(), if args.len() == 5 { args[4].as_str() } else { ".*" });
        },
        "pack" => {
            assert!(args.len() > 3 && args.len() < 6);
            let mut version = 1u8;
            if args.len() == 5 {
                version = match args[4].parse() {
                    Ok(v) => v,
                    Err(_) => {
                        println!("FAILED: {}", E_INVALIDVER); return
                    }
                }
            };
            pack(args[2].as_str(), args[3].as_str(), version);
        },
        _ => usage(),
    }
}
