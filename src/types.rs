/// Semantic operation. Legacy nibble mapping is retained by `from_nibble`;
/// the 0x0320 parser maps its top-level/child headers separately.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordType {
    Eof,
    Add,
    History,
    /// Historical source descriptor with no operation payload.
    Metadata,
    Rename,
    New,
    Modify,
    Mkdir,
    Delete,
    Unknown(u8),
}

impl RecordType {
    pub fn from_nibble(n: u8) -> Self {
        match n {
            1 => Self::Eof,
            2 => Self::Rename,
            3 => Self::New,
            4 => Self::Modify,
            5 => Self::Mkdir,
            6 => Self::Delete,
            other => Self::Unknown(other),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Eof => "EOF",
            Self::Add => "ADD",
            Self::History => "HISTORY",
            Self::Metadata => "METADATA",
            Self::Rename => "RENAME",
            Self::New => "NEW",
            Self::Modify => "MODIFY",
            Self::Mkdir => "MKDIR",
            Self::Delete => "DELETE",
            Self::Unknown(_) => "UNKNOWN",
        }
    }
}

/// Source or destination file version descriptor (§6.3).
/// 10-byte checksum block layout: [b0][b1][w1: 4 LE][w2: 4 LE]
#[derive(Debug, Clone, Default)]
pub struct EntryDescriptor {
    pub short_name: String,
    pub long_name: Option<String>,
    pub attributes: u16,
    pub raw_descriptor: [u8; 24],
    pub raw_checksum: [u8; 10],
    pub extra_timestamps: Option<[u8; 8]>,
    pub inherited: bool,
    pub file_size: u32,
    /// Weak length accumulator mod 31.
    pub b0: u8,
    /// Weak length accumulator mod 30.
    pub b1: u8,
    /// 31-bit rolling checksum (rotl8 within 31 bits), top bit masked.
    pub w1: u32,
    /// 30-bit rolling checksum (rotl8 within 30 bits), top 2 bits masked.
    pub w2: u32,
}

#[derive(Debug, Clone)]
pub struct RtpHeader {
    pub version: u16,
    pub flags: u16,
    pub ext_type_flags: u32,
    pub option_flags: u16,
    /// Legacy field; zero for 0x0320 (size semantics are unproven).
    pub patch_total_size: u32,
    pub opaque: Vec<u8>,
    pub reserved_tail: u32,
    pub default_attrs: u16,
    pub cmd_flags: u16,
    pub combine_mode_id: Option<u32>,
    /// (ext_type_flags >> 16) & 1 — extra timestamps + alt-path in entries.
    pub extra_mode: bool,
}

#[derive(Debug, Clone, Default)]
pub struct FileRecord {
    pub children: Vec<FileRecord>,
    pub expanded_size: Option<u32>,
    pub option_flags: u32,
    pub directory_indices: Vec<usize>,
    pub metadata: [u8; 10],
    pub rec_type: RecordType,
    pub rec_flags: u16,
    pub filename: String,
    pub src_path: Option<String>,
    pub dst_path: Option<String>,
    pub file_mod_flags: u16,
    /// Destination size, or legacy NEW source-descriptor size.
    pub new_file_size: u32,
    /// Byte offset within the raw RTP data where the compressed diff starts.
    pub patch_data_offset: usize,
    /// Compressed MODIFY program or full ADD body length.
    pub patch_data_size: usize,
    /// Number of source file versions referenced by this record.
    pub src_count: i64,
    pub src_entries: Vec<EntryDescriptor>,
    pub dst_entries: Vec<EntryDescriptor>,
}

impl FileRecord {
    pub fn has_diff(&self) -> bool {
        matches!(self.rec_type, RecordType::Modify | RecordType::Add) && self.patch_data_size > 0
    }
}

/// Parsed RTP patch file.
pub struct RtpPatch {
    pub header: RtpHeader,
    pub dirs: Vec<String>,
    pub records: Vec<FileRecord>,
    /// Raw bytes of the .rtp file, kept for extracting compressed diffs.
    pub raw: Vec<u8>,
}

impl Default for RecordType {
    fn default() -> Self { Self::Eof }
}

impl RtpPatch {
    /// Ordinary actions in file order, expanding HISTORY groups into transitions.
    pub fn operations(&self) -> impl Iterator<Item = &FileRecord> {
        self.records.iter().flat_map(|r| {
            if r.rec_type == RecordType::History { r.children.as_slice() }
            else { std::slice::from_ref(r) }
        })
    }
}
