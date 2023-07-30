// https://github.com/freebsd/freebsd-src/tree/main/sys/contrib/libnv
// https://github.com/freebsd/freebsd-src/blob/main/sys/sys/nv.h
use std::{collections::HashMap, error::Error, ffi::CStr, fmt};

/// `NV_HEADER_SIZE` is for both: `nvlist_header` and `nvpair_header`.
const NV_HEADER_SIZE: usize = 19;
const NV_NAME_MAX: u16 = 2048;
const NVLIST_HEADER_MAGIC: u8 = 0x6c; // 'l'
const NVLIST_HEADER_VERSION: u8 = 0;
// Public flags
// Perform case-insensitive lookups of provided names.
// const NV_FLAG_IGNORE_CASE: u8 = 1;
// Names don't have to be unique.
// const NV_FLAG_NO_UNIQUE: u8 = 2;
// Private flags
const NV_FLAG_BIG_ENDIAN: u8 = 0x80;
// const NV_FLAG_IN_ARRAY: u8 = 0x100;

#[repr(u8)]
enum NvType {
    None,
    Null,
    Bool,
    Number,
    String,
    NvList,
    Descriptor,
    Binary,
    BoolArray,
    NumberArray,
    StringArray,
    NvListArray,
    DescriptorArray,
    // must have a parent
    NvListArrayNext = 254,
    NvListAUp,
}

impl From<u8> for NvType {
    fn from(val: u8) -> Self {
        match val {
            1 => Self::Null,
            2 => Self::Bool,
            3 => Self::Number,
            4 => Self::String,
            5 => Self::NvList,
            6 => Self::Descriptor,
            7 => Self::Binary,
            8 => Self::BoolArray,
            9 => Self::NumberArray,
            10 => Self::StringArray,
            11 => Self::NvListArray,
            12 => Self::DescriptorArray,
            254 => Self::NvListArrayNext,
            255 => Self::NvListAUp,
            _ => Self::None,
        }
    }
}

/// `NvList` is a name-value list.
#[derive(Debug)]
pub struct NvList<'a> {
    items: HashMap<&'a str, NvValue<'a>>,
    is_big_endian: bool,
}

#[derive(Debug)]
pub enum NvValue<'a> {
    Null,
    Bool(bool),
    Number(u64),
    String(&'a str),
    NvList(NvList<'a>),
    Descriptor, // not implemented
    Binary(&'a [u8]),
    NvListArray(Vec<NvList<'a>>),
    // TODO: cover other variants
}

#[derive(Debug)]
pub enum NvListError {
    ArrayNextHack(usize),
    NotEnoughBytes,
    WrongHeader,
    WrongName,
    WrongPair,
    WrongPairData,
}

impl Error for NvListError {}

impl fmt::Display for NvListError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ArrayNextHack(_) => write!(f, "end of array"),
            Self::NotEnoughBytes => write!(f, "not enough bytes"),
            Self::WrongHeader => write!(f, "wrong header"),
            Self::WrongName => write!(f, "wrong name"),
            Self::WrongPair => write!(f, "wrong name-value pair"),
            Self::WrongPairData => write!(f, "wrong name-value pair data"),
        }
    }
}

impl<'a> Default for NvList<'a> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> NvList<'a> {
    #[must_use]
    pub fn new() -> Self {
        Self {
            items: HashMap::new(),
            #[cfg(target_endian = "big")]
            is_big_endian: true,
            #[cfg(target_endian = "little")]
            is_big_endian: false,
        }
    }

    pub fn debug(&self) {
        println!("{:#?}", self.items);
    }

    fn read_u16(&self, buf: &[u8]) -> Result<u16, NvListError> {
        if let Ok(bytes) = <[u8; 2]>::try_from(buf) {
            Ok(if self.is_big_endian {
                u16::from_be_bytes(bytes)
            } else {
                u16::from_le_bytes(bytes)
            })
        } else {
            Err(NvListError::NotEnoughBytes)
        }
    }

    fn read_u64(&self, buf: &[u8]) -> Result<u64, NvListError> {
        if let Ok(bytes) = <[u8; 8]>::try_from(buf) {
            Ok(if self.is_big_endian {
                u64::from_be_bytes(bytes)
            } else {
                u64::from_le_bytes(bytes)
            })
        } else {
            Err(NvListError::NotEnoughBytes)
        }
    }

    /// Unpack binary representation of name-value list.
    ///
    /// # Errors
    /// Return `Err` when buffer contains invalid data.
    pub fn unpack(&mut self, buf: &'a [u8]) -> Result<usize, NvListError> {
        let length = buf.len();
        // check header
        if length < NV_HEADER_SIZE {
            return Err(NvListError::NotEnoughBytes);
        }
        if buf[0] != NVLIST_HEADER_MAGIC || buf[1] != NVLIST_HEADER_VERSION {
            return Err(NvListError::WrongHeader);
        }
        self.is_big_endian = buf[2] & NV_FLAG_BIG_ENDIAN != 0;

        let descriptors = self.read_u64(&buf[3..11])?;
        let size = self.read_u64(&buf[11..19])? as usize;
        println!("header {descriptors} {size}");

        // check total size
        if length < NV_HEADER_SIZE + size {
            return Err(NvListError::NotEnoughBytes);
        }

        let mut index = NV_HEADER_SIZE;
        while index < size {
            match self.nvpair_unpack(&buf[index..]) {
                Ok(count) => index += count,
                Err(NvListError::ArrayNextHack(count)) => {
                    return Ok(index + count);
                }
                Err(err) => return Err(err),
            }
        }

        Ok(index)
    }

    /// Unpack binary name-value pair and return number of consumed bytes.
    ///
    /// # Errors
    /// Return `Err` when buffer contains invalid data.
    fn nvpair_unpack(&mut self, buf: &'a [u8]) -> Result<usize, NvListError> {
        let pair_type = NvType::from(buf[0]);
        let name_size = self.read_u16(&buf[1..3])?;
        if name_size > NV_NAME_MAX {
            return Err(NvListError::WrongPair);
        }
        let size = self.read_u64(&buf[3..11])? as usize;
        // Used only for array types.
        let mut item_count = self.read_u64(&buf[11..NV_HEADER_SIZE])?;
        let mut index = NV_HEADER_SIZE + name_size as usize;
        let name = CStr::from_bytes_with_nul(&buf[NV_HEADER_SIZE..index])
            .map_err(|_| NvListError::WrongName)?
            .to_str()
            .map_err(|_| NvListError::WrongName)?;
        println!("pair: {name_size} {size} {item_count} {name}");

        let value = match pair_type {
            NvType::Null => {
                if size != 0 {
                    return Err(NvListError::WrongPairData);
                }
                println!("Null");
                NvValue::Null
            }
            NvType::Bool => {
                if size != 1 {
                    return Err(NvListError::WrongPairData);
                }
                let boolean = buf[index] != 0;
                println!("Bool {boolean}");
                NvValue::Bool(boolean)
            }
            NvType::Number => {
                if size != 8 {
                    return Err(NvListError::WrongPairData);
                }
                let number = self.read_u64(&buf[index..index + size])?;
                println!("Number {number}");
                NvValue::Number(number)
            }
            NvType::String => {
                if size == 0 {
                    return Err(NvListError::WrongPairData);
                }
                let string = CStr::from_bytes_with_nul(&buf[index..index + size])
                    .map_err(|_| NvListError::WrongName)?
                    .to_str()
                    .map_err(|_| NvListError::WrongName)?;
                println!("String {string}");
                NvValue::String(string)
            }
            NvType::NvList => {
                println!("NvList");
                // TODO: read list elements
                NvValue::NvList(NvList::new())
            }
            NvType::Binary => {
                if size == 0 {
                    return Err(NvListError::WrongPairData);
                }
                let binary = &buf[index..index + size];
                println!("Binary {binary:?}");
                NvValue::Binary(binary)
            }
            NvType::NvListArray => {
                println!("NvListArray");
                if size != 0 || item_count == 0 {
                    return Err(NvListError::WrongPairData);
                }
                let mut array = Vec::with_capacity(item_count as usize);
                while item_count != 0 {
                    let mut list = NvList::new();
                    index += list.unpack(&buf[index..])?;
                    array.push(list);
                    item_count -= 1;
                }
                NvValue::NvListArray(array)
            }
            // This is a nasty hack: this type means we've reach the last item in the array.
            // Stop processing the array regardless of size in (nested) NvList header.
            NvType::NvListArrayNext => {
                println!("NvListArrayNext");
                return if size != 0 || item_count != 0 {
                    Err(NvListError::WrongPairData)
                } else {
                    Err(NvListError::ArrayNextHack(index))
                };
            }
            _ => unimplemented!(),
        };
        self.items.insert(name, value);

        Ok(index + size)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_nvlist_unpack() {
        #[rustfmt::skip]
        let data = [
            // *** nvlist_header (19 bytes)
            108, // nvlh_magic
            0,   // nvlh_version
            0,   // nvlh_flags
            0, 0, 0, 0, 0, 0, 0, 0, // nvlh_descriptors
            39 + 19, 0, 0, 0, 0, 0, 0, 0, // nvlh_size
            // *** data (nvlh_size bytes)
            // *** nvpair_header (19 bytes)
            3, // nvph_type = NV_TYPE_NUMBER
            12, 0, // nvph_namesize (incl. NUL)
            8, 0, 0, 0, 0, 0, 0, 0, // nvph_datasize
            0, 0, 0, 0, 0, 0, 0, 0, // nvph_nitems
            108, 105, 115, 116, 101, 110, 45, 112, 111, 114, 116, 0, // "listen-port\0"
            57, 48, 0, 0, 0, 0, 0, 0, // 18519

            1, // nvph_type = NV_TYPE_NULL
            4, 0, // nvph_namesize (incl. NUL)
            0, 0, 0, 0, 0, 0, 0, 0, // nvph_datasize
            0, 0, 0, 0, 0, 0, 0, 0, // nvph_nitems
            'n' as u8, 'u' as u8, 'l' as u8, 0,

            11, // nvph_type = NV_TYPE_NVLIST_ARRAY
            6, 0, // nvph_namesize (incl. NUL)
            0, 0, 0, 0, 0, 0, 0, 0, // nvph_datasize (ZERO!)
            1, 0, 0, 0, 0, 0, 0, 0, // nvph_nitems
            112, 101, 101, 114, 115, 0, // "peers\0"

            // == item #0 - nvlist
            108, // nvlh_magic
            0, // nvlh_version
            0, // nvlh_flags
            0, 0, 0, 0, 0, 0, 0, 0, // nvlh_descriptors
            75, 1, 0, 0, 0, 0, 0, 0, // nvlh_size

            7, // nvph_type = NV_TYPE_BINARY
            11, 0, // nvph_namesize (incl. NUL)
            32, 0, 0, 0, 0, 0, 0, 0, // nvph_datasize
            0, 0, 0, 0, 0, 0, 0, 0, // nvph_nitems
            112, 117, 98, 108, 105, 99, 45, 107, 101, 121, 0, // "public-key\0"
            220, 98, 132, 114, 211, 195, 157, 56, 63, 135, 95, 253, 123, 132, 59, 218,
            35, 120, 55, 169, 156, 165, 223, 184, 140, 111, 142, 164, 145, 107, 167, 17,

            7, // nvph_type = NV_TYPE_BINARY
            14, 0, // nvph_namesize (incl. NUL)
            32, 0, 0, 0, 0, 0, 0, 0, // nvph_datasize
            0, 0, 0, 0, 0, 0, 0, 0, // nvph_nitems
            112, 114, 101, 115, 104, 97, 114, 101, 100, 45, 107, 101, 121, 0, // "preshared-key\0"
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            
            7, // nvph_type = NV_TYPE_BINARY
            20, 0, // nvph_namesize (incl. NUL)
            16, 0, 0, 0, 0, 0, 0, 0, // nvph_datasize
            0, 0, 0, 0, 0, 0, 0, 0, // nvph_nitems
            108, 97, 115, 116, 45, 104, 97, 110, 100, 115, 104, 97, 107, 101, 45, 116, 105, 109, 101, 0, // "last-handshake-time\0"
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            
            3, // nvph_type = NV_TYPE_NUMBER
            30, 0, // nvph_namesize (incl. NUL)
            8, 0, 0, 0, 0, 0, 0, 0, // nvph_datasize
            0, 0, 0, 0, 0, 0, 0, 0, // nvph_nitems
            112, 101, 114, 115, 105, 115, 116, 101, 110, 116, 45, 107, 101, 101, 112,
            97, 108, 105, 118, 101, 45, 105, 110, 116, 101, 114, 118, 97, 108, 0, // "persistent-keepalive-interval\0"
            0, 0, 0, 0, 0, 0, 0, 0,
            
            3, // nvph_type = NV_TYPE_NUMBER
            9, 0, // nvph_namesize (incl. NUL)
            8, 0, 0, 0, 0, 0, 0, 0, // nvph_datasize
            0, 0, 0, 0, 0, 0, 0, 0, // nvph_nitems
            114, 120, 45, 98, 121, 116, 101, 115, 0, // "rx-bytes\0"
            0, 0, 0, 0, 0, 0, 0, 0,
            
            3, // nvph_type = NV_TYPE_NUMBER
            9, 0, // nvph_namesize (incl. NUL)
            8, 0, 0, 0, 0, 0, 0, 0, // nvph_datasize
            0, 0, 0, 0, 0, 0, 0, 0, // nvph_nitems
            116, 120, 45, 98, 121, 116, 101, 115, 0, // "tx-bytes\0"
            0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let mut nvlist = NvList::new();
        nvlist.unpack(&data).unwrap();
        nvlist.debug();
    }

    #[test]
    fn test_two_peers() {
        #[rustfmt::skip]
        let data = [
            // nvlist
            108, 0, 0, 
            0, 0, 0, 0, 0, 0, 0, 0, 
            121, 3, 0, 0, 0, 0, 0, 0,
            // NV_TYPE_NUMBER
            3, 12, 0,
            8, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            108, 105, 115, 116, 101, 110, 45, 112, 111, 114, 116, 0,
            133, 28, 0, 0, 0, 0, 0, 0,
            // NV_TYPE_BINARY
            7, 11, 0,
            32, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            112, 117, 98, 108, 105, 99, 45, 107, 101, 121, 0,
            77, 206, 217, 13, 140, 115, 50, 63, 20, 85, 182, 151, 82, 219, 246, 40, 224, 195, 180, 210, 240, 16, 47, 189, 89, 167, 240, 131, 81, 17, 68, 111,
            // NV_TYPE_NUMBER
            7, 12, 0,
            32, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            112, 114, 105, 118, 97, 116, 101, 45, 107, 101, 121, 0, 
            184, 70, 130, 139, 240, 172, 115, 210, 42, 253, 145, 16, 84, 163, 217, 206, 219, 207, 194, 29, 250, 97, 48, 232, 184, 78, 19, 62, 194, 45, 133, 77,
            // NV_TYPE_NVLIST_ARRAY
            11, 6, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            2, 0, 0, 0, 0, 0, 0, 0,
            112, 101, 101, 114, 115, 0,
            // nvlist
            108, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            169, 2, 0, 0, 0, 0, 0, 0,
            // NV_TYPE_BINARY
            7, 11, 0,
            32, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            112, 117, 98, 108, 105, 99, 45, 107, 101, 121, 0,
            220, 98, 132, 114, 211, 195, 157, 56, 63, 135, 95, 253, 123, 132, 59, 218, 35, 120, 55, 169, 156, 165, 223, 184, 140, 111, 142, 164, 145, 107, 167, 17,
            // NV_TYPE_BINARY
            7, 14, 0,
            32, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            112, 114, 101, 115, 104, 97, 114, 101, 100, 45, 107, 101, 121, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            // NV_TYPE_BINARY
            7, 20, 0,
            16, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            108, 97, 115, 116, 45, 104, 97, 110, 100, 115, 104, 97, 107, 101, 45, 116, 105, 109, 101, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            // NV_TYPE_NUMBER
            3, 30, 0,
            8, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            112, 101, 114, 115, 105, 115, 116, 101, 110, 116, 45, 107, 101, 101, 112, 97, 108, 105, 118, 101, 45, 105, 110, 116, 101, 114, 118, 97, 108, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            // NV_TYPE_NUMBER
            3, 9, 0,
            8, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            114, 120, 45, 98, 121, 116, 101, 115, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            // NV_TYPE_NUMBER
            3, 9, 0,
            8, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            116, 120, 45, 98, 121, 116, 101, 115, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            // NV_TYPE_NVLIST_ARRAY_NEXT
            254, 1, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            0,
            // nvlist
            108, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            75, 1, 0, 0, 0, 0, 0, 0,
            // NV_TYPE_BINARY
            7, 11, 0,
            32, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            112, 117, 98, 108, 105, 99, 45, 107, 101, 121, 0,
            60, 195, 52, 243, 24, 229, 218, 5, 142, 193, 30, 194, 241, 176, 169, 221, 121, 39, 172, 116, 158, 67, 46, 115, 119, 155, 107, 159, 128, 201, 79, 54,
            // NV_TYPE_BINARY
            7, 14, 0,
            32, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            112, 114, 101, 115, 104, 97, 114, 101, 100, 45, 107, 101, 121, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            // NV_TYPE_BINARY
            7, 20, 0,
            16, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            108, 97, 115, 116, 45, 104, 97, 110, 100, 115, 104, 97, 107, 101, 45, 116, 105, 109, 101, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            // NV_TYPE_NUMBER
            3, 30, 0,
            8, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            112, 101, 114, 115, 105, 115, 116, 101, 110, 116, 45, 107, 101, 101, 112, 97, 108, 105, 118, 101, 45, 105, 110, 116, 101, 114, 118, 97, 108, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            // NV_TYPE_NUMBER
            3, 9, 0,
            8, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            114, 120, 45, 98, 121, 116, 101, 115, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            // NV_TYPE_NUMBER
            3, 9, 0,
            8, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            116, 120, 45, 98, 121, 116, 101, 115, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            // NV_TYPE_NVLIST_ARRAY_NEXT
            254, 1, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            0];
        let mut nvlist = NvList::new();
        nvlist.unpack(&data).unwrap();
        nvlist.debug();
    }
}
