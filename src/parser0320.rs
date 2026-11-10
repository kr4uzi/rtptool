//! Observed extra-entry 0x0320 layout. Unobserved framing fails closed.
use crate::{EntryDescriptor, FileRecord, RecordType, RtpError, RtpHeader, reader::Reader};

fn invalid(message: &str) -> RtpError {
    RtpError::InvalidFormat(message.into())
}

pub(crate) fn string(r: &mut Reader<'_>) -> Result<String, RtpError> {
    let n = r.u8()?;
    let n = if n == 255 { r.u16_le()? as usize } else { n as usize };
    let raw = r.read_exact(n)?;
    if n == 0 { return Ok(String::new()); }
    if raw[n - 1] != 0 { return Err(invalid("unterminated 0x0320 string")); }
    // Corpus names are ASCII; do not silently substitute non-UTF8 path bytes.
    String::from_utf8(raw[..n - 1].to_vec()).map_err(|_| invalid("unsupported pathname encoding"))
}

fn count(r: &mut Reader<'_>) -> Result<usize, RtpError> {
    let n = r.vli()?;
    if n != 1 { return Err(invalid("0x0320 requires one descriptor per operation")); }
    Ok(n as usize)
}

fn checksum(r: &mut Reader<'_>, mut e: EntryDescriptor) -> Result<EntryDescriptor, RtpError> {
    let raw: [u8; 10] = r.read_exact(10)?.try_into().unwrap();
    e.raw_checksum = raw;
    e.b0 = raw[0];
    e.b1 = raw[1];
    e.w1 = u32::from_le_bytes(raw[2..6].try_into().unwrap()) & 0x7fff_ffff;
    e.w2 = u32::from_le_bytes(raw[6..10].try_into().unwrap()) & 0x3fff_ffff;
    if e.b0 != (e.file_size % 31) as u8 || e.b1 != (e.file_size % 30) as u8 {
        return Err(invalid("descriptor length accumulators disagree with size"));
    }
    Ok(e)
}

fn entry(r: &mut Reader<'_>) -> Result<EntryDescriptor, RtpError> {
    let raw: [u8; 24] = r.read_exact(24)?.try_into().unwrap();
    let short = &raw[..13];
    let end = short.iter().position(|b| *b == 0).unwrap_or(13);
    let e = EntryDescriptor {
        file_size: u32::from_le_bytes(raw[16..20].try_into().unwrap()),
        short_name: String::from_utf8_lossy(&short[..end]).into_owned(),
        attributes: u16::from_le_bytes(raw[14..16].try_into().unwrap()),
        raw_descriptor: raw,
        ..Default::default()
    };
    let mut e = checksum(r, e)?;
    e.extra_timestamps = Some(r.read_exact(8)?.try_into().unwrap());
    e.long_name = Some(string(r)?);
    Ok(e)
}

fn body(r: &mut Reader<'_>, rec: &mut FileRecord, previous: Option<&FileRecord>) -> Result<(), RtpError> {
    match rec.rec_type {
        RecordType::Delete | RecordType::Metadata => {
            count(r)?;
            rec.src_entries.push(entry(r)?);
            rec.src_count = 1;
        }
        RecordType::Modify | RecordType::Add => {
            if rec.rec_type == RecordType::Modify {
                rec.file_mod_flags = r.u16_le()?;
                if !matches!(rec.file_mod_flags, 9 | 13) {
                    return Err(invalid("unobserved MODIFY flags"));
                }
                if previous.is_none() { count(r)?; }
                rec.src_count = 1;
            }
            count(r)?;
            rec.expanded_size = Some(r.u32_le()?);
            rec.patch_data_size = r.u32_le()? as usize;
            if rec.rec_type == RecordType::Modify {
                let e = if let Some(prev) = previous {
                    let e = prev.dst_entries.first().ok_or_else(|| invalid("missing inherited destination"))?;
                    let mut inherited = checksum(r, e.clone())?;
                    if inherited.raw_checksum != e.raw_checksum {
                        return Err(invalid("inherited source checksum differs from previous destination"));
                    }
                    inherited.inherited = true;
                    inherited
                } else { entry(r)? };
                rec.src_entries.push(e);
            }
            rec.dst_entries.push(entry(r)?);
            rec.new_file_size = rec.dst_entries[0].file_size;
            rec.patch_data_offset = r.pos;
            let compressed = r.read_exact(rec.patch_data_size)?;
            if !compressed.starts_with(&[0xb5, 0x9c]) { return Err(invalid("missing compressed stream magic")); }
        }
        _ => return Err(invalid("unsupported operation body")),
    }
    Ok(())
}

pub(crate) fn records(r: &mut Reader<'_>, h: &RtpHeader, dirs: &[String]) -> Result<Vec<FileRecord>, RtpError> {
    if h.flags != 0xb7e4 || h.ext_type_flags != 0x10000 || h.option_flags != 8 || h.cmd_flags != 4 {
        return Err(invalid("unobserved 0x0320 header flags/layout"));
    }
    let mut records = Vec::new();
    loop {
        let word = r.u16_le()?;
        if word == 0x1000 {
            if r.remaining() != 0 { return Err(invalid("bytes after EOF")); }
            break;
        }
        if !matches!(word, 0x5806 | 0x4446 | 0x4444 | 0x2446 | 0x3446 | 0x3444) {
            return Err(invalid("unobserved top-level record header"));
        }
        let kind = match word >> 12 {
            2 => RecordType::Add, 3 => RecordType::Delete,
            4 => RecordType::Modify, 5 => RecordType::History,
            _ => unreachable!(),
        };
        let mut rec = FileRecord { rec_type: kind, rec_flags: word, option_flags: h.option_flags as u32, ..Default::default() };
        if word & 2 != 0 {
            rec.option_flags = if kind == RecordType::History { r.u32_le()? } else { r.u16_le()? as u32 };
        }
        if !matches!(rec.option_flags, 8 | 0x1b8) { return Err(invalid("unobserved record options")); }
        if word & 4 != 0 { rec.filename = string(r)?; }
        if rec.option_flags & 0xc0 != 0 {
            for _ in 0..2 {
                let index = r.vli()?;
                if index < 0 || index as usize >= dirs.len() { return Err(invalid("directory index out of range")); }
                rec.directory_indices.push(index as usize);
            }
        }
        let span = if kind == RecordType::History { Some((r.u32_le()? as usize, r.u16_le()? as usize)) } else { None };
        rec.metadata = r.read_exact(10)?.try_into().unwrap();
        if let Some((size, n)) = span {
            let start = r.pos;
            r.read_exact(size)?;
            // Bounded reader retains payload-relative offsets.
            let mut child = Reader { data: &r.data[..r.pos], pos: start };
            for _ in 0..n {
                let word = child.u16_le()?;
                let kind = match word {
                    0x2c2 => RecordType::Add, 0x2c3 => RecordType::Delete,
                    0x243 => RecordType::Metadata, 0x2c4 => RecordType::Modify,
                    _ => return Err(invalid("unobserved history child header")),
                };
                let mut c = FileRecord {
                    rec_type: kind, rec_flags: word, filename: rec.filename.clone(),
                    option_flags: rec.option_flags, directory_indices: rec.directory_indices.clone(),
                    ..Default::default()
                };
                body(&mut child, &mut c, rec.children.last())?;
                rec.children.push(c);
            }
            if child.pos != r.pos || n == 0 { return Err(invalid("history span/count mismatch")); }
            rec.new_file_size = rec.children.last().unwrap().new_file_size;
        } else { body(r, &mut rec, None)?; }
        records.push(rec);
    }
    if h.combine_mode_id != Some(records.len() as u32) { return Err(invalid("header record count mismatch")); }
    Ok(records)
}
