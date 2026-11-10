pub mod apply;
pub mod codec;
pub mod error;
pub mod parser;
mod parser0320;
pub mod reader;
pub mod types;

pub use error::RtpError;
pub use parser::parse;
pub use types::{EntryDescriptor, FileRecord, RecordType, RtpHeader, RtpPatch};

/// 31-bit rolling checksum (w1).
/// Each byte: w1 = rotl8(w1 ^ c) within 31 bits.
pub fn checksum_w1(data: &[u8]) -> u32 {
    let mut w: u32 = 0;
    for &c in data {
        let t = w ^ c as u32;
        w = ((t << 8) | (t >> 23)) & 0x7FFF_FFFF;
    }
    w
}

/// 30-bit rolling checksum (w2).
/// Each byte: w2 = rotl8(w2 ^ c) within 30 bits.
/// This is the value stored in entry descriptors (block10[6..10] & 0x3FFFFFFF).
pub fn checksum_w2(data: &[u8]) -> u32 {
    let mut w: u32 = 0;
    for &c in data {
        let t = w ^ c as u32;
        w = ((t << 8) | (t >> 22)) & 0x3FFF_FFFF;
    }
    w
}

/// High-level: decompress and apply a MODIFY record to a source file.
///
/// Returns the patched bytes. Validates the source checksum if `check_sum` is true.
pub fn patch_file(
    patch: &RtpPatch,
    record: &FileRecord,
    src_data: &[u8],
    check_sum: bool,
) -> Result<Vec<u8>, RtpError> {
    if patch.header.version == 0x0320 {
        return apply_record(patch, record, Some(src_data))?
            .ok_or_else(|| application_error(record, "record deletes the file; use apply_record"));
    }
    if check_sum
        && let Some(e) = record.src_entries.first().filter(|e| e.w2 != 0)
    {
        let actual = checksum_w2(src_data);
        if actual != e.w2 {
            return Err(RtpError::ChecksumMismatch {
                filename: record.filename.clone(),
                expected: e.w2,
                actual,
            });
        }
    }

    let opcodes = codec::decompress(
        &patch.raw,
        record.patch_data_offset,
        record.patch_data_size,
        (record.new_file_size as usize * 4).max(0x40_0000),
    )
    .map_err(|e| RtpError::DecompressError {
        filename: record.filename.clone(),
        detail: e,
    })?;

    let mut result = apply::apply(src_data, &opcodes, record.new_file_size as usize, record.src_count)
        .map_err(|e| match e {
            RtpError::ApplyError { detail, .. } => RtpError::ApplyError {
                filename: record.filename.clone(),
                detail,
            },
            other => other,
        })?;

    result.truncate(record.new_file_size as usize);
    Ok(result)
}

/// Match size and all four checksum fields, including zero-valued checksums.
pub fn descriptor_matches(data: &[u8], e: &EntryDescriptor) -> bool {
    data.len() == e.file_size as usize && signature_matches(signature(data), e)
}

fn signature(data: &[u8]) -> (usize, u32, u32) {
    let (mut w1, mut w2) = (0u32, 0u32);
    for &c in data {
        let t = w1 ^ c as u32;
        w1 = ((t << 8) | (t >> 23)) & 0x7fff_ffff;
        let t = w2 ^ c as u32;
        w2 = ((t << 8) | (t >> 22)) & 0x3fff_ffff;
    }
    (data.len(), w1, w2)
}

fn signature_matches((size, w1, w2): (usize, u32, u32), e: &EntryDescriptor) -> bool {
    size == e.file_size as usize && e.b0 == (size % 31) as u8
        && e.b1 == (size % 30) as u8 && w1 == e.w1 && w2 == e.w2
}

fn application_error(rec: &FileRecord, detail: &str) -> RtpError {
    RtpError::ApplyError { filename: rec.filename.clone(), detail: detail.into() }
}

/// Decode one compressed body with its declared expanded length.
pub fn decode_record(patch: &RtpPatch, rec: &FileRecord) -> Result<Vec<u8>, RtpError> {
    let expected = rec.expanded_size.ok_or_else(|| application_error(rec, "no declared expanded size"))?;
    codec::decompress_exact(&patch.raw, rec.patch_data_offset, rec.patch_data_size, expected as usize)
        .map_err(|detail| RtpError::DecompressError { filename: rec.filename.clone(), detail })
}

/// Apply an observed 0x0320 operation or HISTORY suffix to an optional file.
/// `None` means absent/deleted. Inputs are never mutated. A present input must
/// match a source or the final destination; unknown versions are errors.
/// Already-final data is returned unchanged. Checksums cannot be bypassed here.
pub fn apply_record(patch: &RtpPatch, rec: &FileRecord, source: Option<&[u8]>) -> Result<Option<Vec<u8>>, RtpError> {
    if patch.header.version != 0x0320 { return Err(application_error(rec, "apply_record requires 0x0320")); }
    let steps: &[FileRecord] = if rec.rec_type == RecordType::History { &rec.children } else { std::slice::from_ref(rec) };
    let last = steps.last().ok_or_else(|| application_error(rec, "empty history"))?;
    let source_signature = source.map(signature);
    if let Some(data) = source {
        if last.dst_entries.first().is_some_and(|e| signature_matches(source_signature.unwrap(), e)) {
            return Ok(Some(data.to_vec()));
        }
    } else if last.rec_type == RecordType::Delete {
        return Ok(None);
    }
    // Choose the latest matching source transition. Absence may start at any
    // ADD, including DELETE->ADD histories whose old source is unavailable.
    let start = steps.iter().rposition(|s| match source {
        Some(_) => s.src_entries.first().is_some_and(|e| signature_matches(source_signature.unwrap(), e)),
        None => s.rec_type == RecordType::Add,
    }).ok_or_else(|| application_error(rec, "no matching source version in history"))?;
    let mut current = source.map(<[u8]>::to_vec);
    for step in &steps[start..] {
        match step.rec_type {
            RecordType::Metadata => {
                let data = current.as_deref().ok_or_else(|| application_error(step, "metadata source absent"))?;
                if !descriptor_matches(data, &step.src_entries[0]) { return Err(application_error(step, "source size/checksums mismatch")); }
            }
            RecordType::Delete => {
                let data = current.as_deref().ok_or_else(|| application_error(step, "DELETE source absent"))?;
                if !descriptor_matches(data, &step.src_entries[0]) { return Err(application_error(step, "DELETE source size/checksums mismatch")); }
                current = None;
            }
            RecordType::Add | RecordType::Modify => {
                let decoded = decode_record(patch, step)?;
                let result = if step.rec_type == RecordType::Add {
                    if current.is_some() { return Err(application_error(step, "ADD target already exists")); }
                    decoded
                } else {
                    let data = current.as_deref().ok_or_else(|| application_error(step, "MODIFY source absent"))?;
                    if !descriptor_matches(data, &step.src_entries[0]) { return Err(application_error(step, "source size/checksums mismatch")); }
                    apply::apply_exact(data, &decoded, step.new_file_size as usize)?
                };
                if !descriptor_matches(&result, &step.dst_entries[0]) { return Err(application_error(step, "destination size/checksums mismatch")); }
                current = Some(result);
            }
            _ => return Err(application_error(step, "unsupported history operation")),
        }
    }
    Ok(current)
}
