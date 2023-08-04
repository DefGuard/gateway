// https://github.com/freebsd/freebsd-src/tree/main/sys/contrib/libnv
// https://github.com/freebsd/freebsd-src/blob/main/sys/sys/nv.h
use std::{error::Error, ffi::CStr, fmt};

/// `NV_HEADER_SIZE` is for both: `nvlist_header` and `nvpair_header`.
const NV_HEADER_SIZE: usize = 19;
const NV_NAME_MAX: usize = 2048;
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

#[derive(Debug)]
#[repr(u8)]
pub enum NvType {
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

#[derive(Debug)]
pub enum NvValue<'a> {
    Null,
    Bool(bool),
    Number(u64),
    String(&'a str),
    NvList(NvList<'a>),
    Descriptor, // not implemented
    Binary(&'a [u8]),
    BoolArray(Vec<bool>),
    NumberArray(Vec<u64>),
    StringArray(Vec<&'a str>),
    NvListArray(Vec<NvList<'a>>),
    DescriptorArray, // not implemented
    NvListArrayNext,
    // NvListAUp,
}

impl<'a> NvValue<'a> {
    /// Return number of bytes this value occupies when packed.
    #[must_use]
    pub fn byte_size(&self) -> usize {
        match self {
            Self::Null | Self::Descriptor | Self::DescriptorArray => 0,
            Self::Bool(_) => 1,
            Self::Number(_) => 8,
            Self::String(s) => s.len() + 1, // +1 for NUL
            Self::NvList(list) => list.byte_size(),
            Self::Binary(b) => b.len(),
            Self::BoolArray(v) => v.len(),
            Self::NumberArray(v) => v.len() * 4,
            Self::StringArray(v) => v.iter().fold(0, |size, el| size + el.len() + 1),
            Self::NvListArray(v) => v
                .iter()
                .fold(0, |size, el| size + el.byte_size() + NV_HEADER_SIZE),
            Self::NvListArrayNext => 0,
        }
    }

    /// Return value that should be stored in `nvph_datasize`.
    /// Note that arrays store 0.
    #[must_use]
    pub fn data_size(&self) -> usize {
        match self {
            Self::Null | Self::Descriptor | Self::DescriptorArray => 0,
            Self::Bool(_) => 1,
            Self::Number(_) => 8,
            Self::String(s) => s.len() + 1, // +1 for NUL
            Self::NvList(_) => 0,           // FIXME: not sure about this
            Self::Binary(b) => b.len(),
            Self::BoolArray(_)
            | Self::NumberArray(_)
            | Self::StringArray(_)
            | Self::NvListArray(_) => 0,
            Self::NvListArrayNext => 0,
        }
    }

    #[must_use]
    pub fn nv_type(&self) -> NvType {
        match self {
            Self::Null => NvType::Null,
            Self::Bool(_) => NvType::Bool,
            Self::Number(_) => NvType::Number,
            Self::String(_) => NvType::String,
            Self::NvList(_) => NvType::NvList,
            Self::Descriptor => NvType::Descriptor,
            Self::Binary(_) => NvType::Binary,
            Self::BoolArray(_) => NvType::BoolArray,
            Self::NumberArray(_) => NvType::NumberArray,
            Self::StringArray(_) => NvType::StringArray,
            Self::NvListArray(_) => NvType::NvListArray,
            Self::DescriptorArray => NvType::DescriptorArray,
            Self::NvListArrayNext => NvType::NvListArrayNext,
        }
    }

    #[must_use]
    pub fn no_items(&self) -> usize {
        match self {
            Self::BoolArray(v) => v.len(),
            Self::NumberArray(v) => v.len(),
            Self::StringArray(v) => v.len(),
            Self::NvListArray(v) => v.len(),
            _ => 0, // non-array
        }
    }
}

#[derive(Debug)]
pub enum NvListError {
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
            Self::NotEnoughBytes => write!(f, "not enough bytes"),
            Self::WrongHeader => write!(f, "wrong header"),
            Self::WrongName => write!(f, "wrong name"),
            Self::WrongPair => write!(f, "wrong name-value pair"),
            Self::WrongPairData => write!(f, "wrong name-value pair data"),
        }
    }
}

/// `NvList` is a name-value list.
type NameValue<'a> = (&'a str, NvValue<'a>);
#[derive(Debug)]
pub struct NvList<'a> {
    items: Vec<NameValue<'a>>,
    is_big_endian: bool,
}

impl<'a> Default for NvList<'a> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> NvList<'a> {
    /// Create new `NvList`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            items: Vec::new(),
            #[cfg(target_endian = "big")]
            is_big_endian: true,
            #[cfg(target_endian = "little")]
            is_big_endian: false,
        }
    }

    pub fn debug(&self) {
        println!("{:?}", self.items);
    }

    /// Get value for a given `name`.
    pub fn get(&self, name: &str) -> Option<&NvValue> {
        self.items.iter().find(|(n, _)| n == &name).map(|(_, v)| v)
    }

    fn load_u16(&self, buf: &[u8]) -> Result<u16, NvListError> {
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

    fn load_u64(&self, buf: &[u8]) -> Result<u64, NvListError> {
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

    fn store_u16(&self, value: u16, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&if self.is_big_endian {
            value.to_be_bytes()
        } else {
            value.to_le_bytes()
        });
    }

    fn store_u64(&self, value: u64, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&if self.is_big_endian {
            value.to_be_bytes()
        } else {
            value.to_le_bytes()
        });
    }

    /// Return number of bytes this list occupies when packed.
    #[must_use]
    fn byte_size(&self) -> usize {
        let mut size = 0;
        for (name, value) in &self.items {
            size += NV_HEADER_SIZE + name.len() + 1; // +1 for NUL
            size += value.byte_size();
        }

        size
    }

    /// Pack name-value list to binary representation.
    pub fn pack(&self, buf: &mut Vec<u8>) {
        // pack header
        buf.push(NVLIST_HEADER_MAGIC);
        buf.push(NVLIST_HEADER_VERSION);
        buf.push(if self.is_big_endian {
            NV_FLAG_BIG_ENDIAN
        } else {
            0
        });
        // descriptors
        self.store_u64(0, buf);
        self.store_u64(self.byte_size() as u64, buf);

        for (name, value) in &self.items {
            buf.push(value.nv_type() as u8);
            // name length
            let name_len = name.len() + 1;
            if name_len > NV_NAME_MAX {
                // error
            }
            self.store_u16(name_len as u16, buf);
            // data size
            self.store_u64(value.data_size() as u64, buf);
            // no. items
            self.store_u64(value.no_items() as u64, buf);
            // name
            buf.extend_from_slice(name.as_bytes());
            buf.push(0); // NUL

            match value {
                NvValue::Bool(boolean) => buf.push(u8::from(*boolean)),
                NvValue::Number(number) => self.store_u64(*number, buf),
                NvValue::String(string) => {
                    buf.extend_from_slice(string.as_bytes());
                    buf.push(0); // NUL
                }
                NvValue::Binary(bytes) => buf.extend_from_slice(bytes),
                NvValue::NvListArray(nvlist_array) => {
                    for nvlist in nvlist_array {
                        nvlist.pack(buf);
                    }
                }
                _ => (),
            }
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

        let descriptors = self.load_u64(&buf[3..11])?;
        let size = self.load_u64(&buf[11..19])? as usize;
        println!("header {descriptors} {size}");

        // check total size
        if length < NV_HEADER_SIZE + size {
            return Err(NvListError::NotEnoughBytes);
        }

        let mut index = NV_HEADER_SIZE;
        while index < size {
            match self.nvpair_unpack(&buf[index..]) {
                Ok((count, last_element)) => {
                    index += count;
                    if last_element {
                        break;
                    }
                }
                Err(err) => return Err(err),
            }
        }

        Ok(index)
    }

    /// Unpack binary name-value pair and return number of consumed bytes and
    /// a flag indicating if array processing should be stopped (`true`), or not (`false`).
    ///
    /// # Errors
    /// Return `Err` when buffer contains invalid data.
    fn nvpair_unpack(&mut self, buf: &'a [u8]) -> Result<(usize, bool), NvListError> {
        let pair_type = NvType::from(buf[0]);
        let name_size = self.load_u16(&buf[1..3])? as usize;
        if name_size > NV_NAME_MAX {
            return Err(NvListError::WrongPair);
        }
        let size = self.load_u64(&buf[3..11])? as usize;
        // Used only for array types.
        let mut item_count = self.load_u64(&buf[11..NV_HEADER_SIZE])?;
        let mut index = NV_HEADER_SIZE + name_size;
        println!("pair: name_size={name_size} size={size} item_count={item_count}");
        let name = CStr::from_bytes_with_nul(&buf[NV_HEADER_SIZE..index])
            .map_err(|_| NvListError::WrongName)?
            .to_str()
            .map_err(|_| NvListError::WrongName)?;
        // println!("type: {pair_type:?}");
        let mut last_element = false;

        let value = match pair_type {
            NvType::Null => {
                if size != 0 {
                    return Err(NvListError::WrongPairData);
                }
                NvValue::Null
            }
            NvType::Bool => {
                if size != 1 {
                    return Err(NvListError::WrongPairData);
                }
                let boolean = buf[index] != 0;
                NvValue::Bool(boolean)
            }
            NvType::Number => {
                if size != 8 {
                    return Err(NvListError::WrongPairData);
                }
                let number = self.load_u64(&buf[index..index + size])?;
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
                NvValue::String(string)
            }
            NvType::NvList => {
                // TODO: read list elements
                NvValue::NvList(NvList::new())
            }
            NvType::Binary => {
                if size == 0 {
                    return Err(NvListError::WrongPairData);
                }
                let binary = &buf[index..index + size];
                NvValue::Binary(binary)
            }
            NvType::NvListArray => {
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
            // Stop processing the array regardless of `nvlh_size` in (nested) NvList header.
            NvType::NvListArrayNext => {
                if size != 0 || item_count != 0 {
                    return Err(NvListError::WrongPairData);
                }
                last_element = true;
                NvValue::NvListArrayNext
            }
            _ => unimplemented!(),
        };
        println!("insert '{name}' = {value:?}");
        self.items.push((name, value));

        Ok((index + size, last_element))
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
            39 + 23, 0, 0, 0, 0, 0, 0, 0, // nvlh_size
            // *** data (nvlh_size bytes)
            // *** nvpair_header (19 bytes)
            3, // nvph_type = NV_TYPE_NUMBER
            12, 0, // nvph_namesize (incl. NUL)
            8, 0, 0, 0, 0, 0, 0, 0, // nvph_datasize
            0, 0, 0, 0, 0, 0, 0, 0, // nvph_nitems
            108, 105, 115, 116, 101, 110, 45, 112, 111, 114, 116, 0, // "listen-port\0"
            57, 48, 0, 0, 0, 0, 0, 0, // 12345

            1, // nvph_type = NV_TYPE_NULL
            4, 0, // nvph_namesize (incl. NUL)
            0, 0, 0, 0, 0, 0, 0, 0, // nvph_datasize
            0, 0, 0, 0, 0, 0, 0, 0, // nvph_nitems
            'n' as u8, 'u' as u8, 'l' as u8, 0,
        ];
        let mut nvlist = NvList::new();
        nvlist.unpack(&data).unwrap();
        nvlist.debug();

        let mut buf = Vec::new();
        nvlist.pack(&mut buf);

        let mut nvlist = NvList::new();
        nvlist.unpack(&buf).unwrap();
        nvlist.debug();

        assert_eq!(data.as_slice(), buf.as_slice());
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
            108, 105, 115, 116, 101, 110, 45, 112, 111, 114, 116, 0, // "listen-port\0"
            133, 28, 0, 0, 0, 0, 0, 0,
            // NV_TYPE_BINARY
            7, 11, 0,
            32, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            112, 117, 98, 108, 105, 99, 45, 107, 101, 121, 0, // "public-key\0"
            77, 206, 217, 13, 140, 115, 50, 63, 20, 85, 182, 151, 82, 219, 246, 40, 224, 195, 180, 210, 240, 16, 47, 189, 89, 167, 240, 131, 81, 17, 68, 111,
            // NV_TYPE_NUMBER
            7, 12, 0,
            32, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            112, 114, 105, 118, 97, 116, 101, 45, 107, 101, 121, 0, // "private-key\0"
            184, 70, 130, 139, 240, 172, 115, 210, 42, 253, 145, 16, 84, 163, 217, 206, 219, 207, 194, 29, 250, 97, 48, 232, 184, 78, 19, 62, 194, 45, 133, 77,
            // NV_TYPE_NVLIST_ARRAY
            11, 6, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            2, 0, 0, 0, 0, 0, 0, 0,
            112, 101, 101, 114, 115, 0, // "peers\0"
            // nvlist
            108, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            75, 1, 0, 0, 0, 0, 0, 0, // MODIFIED
            //169, 2, 0, 0, 0, 0, 0, 0, // ORIGINAL
            // NV_TYPE_BINARY
            7, 11, 0,
            32, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            112, 117, 98, 108, 105, 99, 45, 107, 101, 121, 0, // "public-key\0"
            220, 98, 132, 114, 211, 195, 157, 56, 63, 135, 95, 253, 123, 132, 59, 218, 35, 120, 55, 169, 156, 165, 223, 184, 140, 111, 142, 164, 145, 107, 167, 17,
            // NV_TYPE_BINARY
            7, 14, 0,
            32, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            112, 114, 101, 115, 104, 97, 114, 101, 100, 45, 107, 101, 121, 0, // "preshared-key\0"
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            // NV_TYPE_BINARY
            7, 20, 0,
            16, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            108, 97, 115, 116, 45, 104, 97, 110, 100, 115, 104, 97, 107, 101, 45, 116, 105, 109, 101, 0, // "last-handshake-time\0"
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            // NV_TYPE_NUMBER
            3, 30, 0,
            8, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            112, 101, 114, 115, 105, 115, 116, 101, 110, 116, 45, 107, 101, 101, 112, 97, 108, 105, 118, 101, 45, 105, 110, 116, 101, 114, 118, 97, 108, 0, // "persistent-keepalive-interval\0"
            0, 0, 0, 0, 0, 0, 0, 0,
            // NV_TYPE_NUMBER
            3, 9, 0,
            8, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            114, 120, 45, 98, 121, 116, 101, 115, 0, // "rx-bytes\0"
            0, 0, 0, 0, 0, 0, 0, 0,
            // NV_TYPE_NUMBER
            3, 9, 0,
            8, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            116, 120, 45, 98, 121, 116, 101, 115, 0, // "tx-bytes\0"
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
            112, 117, 98, 108, 105, 99, 45, 107, 101, 121, 0, // "public-key\0"
            60, 195, 52, 243, 24, 229, 218, 5, 142, 193, 30, 194, 241, 176, 169, 221, 121, 39, 172, 116, 158, 67, 46, 115, 119, 155, 107, 159, 128, 201, 79, 54,
            // NV_TYPE_BINARY
            7, 14, 0,
            32, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            112, 114, 101, 115, 104, 97, 114, 101, 100, 45, 107, 101, 121, 0, // "preshared-key\0"
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            // NV_TYPE_BINARY
            7, 20, 0,
            16, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            108, 97, 115, 116, 45, 104, 97, 110, 100, 115, 104, 97, 107, 101, 45, 116, 105, 109, 101, 0, // "last-handshake-time\0"
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            // NV_TYPE_NUMBER
            3, 30, 0,
            8, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            112, 101, 114, 115, 105, 115, 116, 101, 110, 116, 45, 107, 101, 101, 112, 97, 108, 105, 118, 101, 45, 105, 110, 116, 101, 114, 118, 97, 108, 0, // "persistent-keepalive-interval\0"
            0, 0, 0, 0, 0, 0, 0, 0,
            // NV_TYPE_NUMBER
            3, 9, 0,
            8, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            114, 120, 45, 98, 121, 116, 101, 115, 0, // "rx-bytes\0"
            0, 0, 0, 0, 0, 0, 0, 0,
            // NV_TYPE_NUMBER
            3, 9, 0,
            8, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            116, 120, 45, 98, 121, 116, 101, 115, 0, // "tx-bytes\0"
            0, 0, 0, 0, 0, 0, 0, 0,
            // NV_TYPE_NVLIST_ARRAY_NEXT
            254, 1, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            0];
        let mut nvlist = NvList::new();
        nvlist.unpack(&data).unwrap();
        nvlist.debug();

        let mut buf = Vec::new();
        nvlist.pack(&mut buf);
        println!("PACKED {}/{} {buf:?}", data.len(), buf.len());

        let mut nvlist = NvList::new();
        nvlist.unpack(&buf).unwrap();
        nvlist.debug();

        if data.len() == buf.len() {
            for (i, v) in buf.iter().enumerate() {
                if v != &data[i] {
                    println!("💩 {i:4} {:3} != {:3}", data[i], v);
                }
            }
        }

        assert_eq!(data.as_slice(), buf.as_slice());
    }
}
