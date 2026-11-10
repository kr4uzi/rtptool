use rtptool::{RecordType, apply_record, parse};

// All fixtures are generated from the small, original strings below.
fn u16v(out: &mut Vec<u8>, n: u16) { out.extend(n.to_le_bytes()); }
fn u32v(out: &mut Vec<u8>, n: u32) { out.extend(n.to_le_bytes()); }
fn string(out: &mut Vec<u8>, name: &str) { out.push((name.len()+1) as u8); out.extend(name.bytes()); out.push(0); }
fn check(data: &[u8]) -> Vec<u8> {
    let mut out = vec![(data.len()%31) as u8, (data.len()%30) as u8];
    u32v(&mut out, rtptool::checksum_w1(data)); u32v(&mut out, rtptool::checksum_w2(data)); out
}
fn entry(out: &mut Vec<u8>, data: &[u8]) {
    let mut raw = [0;24]; raw[..5].copy_from_slice(b"X.TXT");
    raw[16..20].copy_from_slice(&(data.len() as u32).to_le_bytes());
    out.extend(raw); out.extend(check(data)); out.extend([0;8]); string(out,"x.txt");
}
fn bits(out: &mut Vec<bool>, n: u32, value: u32) { for i in (0..n).rev() { out.push(value & (1<<i) != 0); } }
fn compressed(data: &[u8]) -> Vec<u8> {
    let mut b = vec![];
    for (n,v) in [(16,0xb59c),(8,1),(8,255),(12,64),(12,16),(4,8)] { bits(&mut b,n,v); }
    for &v in data { bits(&mut b,1,0); bits(&mut b,8,v as u32); }
    // Distance-zero terminator: match flag, low distance, escape, raw high distance.
    for (n,v) in [(1,1),(7,0),(1,0),(6,0)] { bits(&mut b,n,v); }
    b.chunks(8).map(|c| c.iter().enumerate().fold(0,|v,(i,bit)| v | ((*bit as u8) << (7-i)))).collect()
}
fn body(out: &mut Vec<u8>, old: Option<&[u8]>, new: &[u8], program: &[u8], inherited: bool) {
    if old.is_some() { u16v(out,9); if !inherited {out.push(1);} }
    out.push(1); u32v(out,program.len() as u32);
    let c = compressed(program); u32v(out,c.len() as u32);
    if let Some(old) = old { if inherited {out.extend(check(old));} else {entry(out,old);} }
    entry(out,new); out.extend(c);
}
fn operation(kind: u16, old: Option<&[u8]>, new: &[u8], program: &[u8]) -> Vec<u8> {
    let mut out = vec![]; u16v(&mut out,kind<<12 | 0x446); u16v(&mut out,8); string(&mut out,"dir\\x.txt"); out.extend([0;10]);
    if kind == 3 {out.push(1);entry(&mut out,old.unwrap());} else {body(&mut out,old,new,program,false);}
    out
}
fn history(children: &[Vec<u8>]) -> Vec<u8> {
    let mut out=vec![];u16v(&mut out,0x5806);u32v(&mut out,8);string(&mut out,"dir\\x.txt");
    u32v(&mut out,children.iter().map(Vec::len).sum::<usize>() as u32);u16v(&mut out,children.len() as u16);out.extend([0;10]);
    for c in children {out.extend(c);}out
}
fn container(records: &[Vec<u8>]) -> Vec<u8> {
    let mut out=b"K*\x20\x03".to_vec();u16v(&mut out,0xb7e4);u32v(&mut out,0x10000);u16v(&mut out,8);
    out.extend([0;12]);u16v(&mut out,0);u16v(&mut out,0);u16v(&mut out,4);u32v(&mut out,records.len() as u32);u32v(&mut out,0x0acadc6b);u16v(&mut out,0);
    for r in records {out.extend(r);}u16v(&mut out,0x1000);out
}
fn transition(old: &[u8], new: &[u8], inherited: bool) -> Vec<u8> {
    let mut out=vec![];u16v(&mut out,0x2c4);
    let mut program=vec![5]; program.extend(new);program.push(1);
    body(&mut out,Some(old),new,&program,inherited);out
}
#[test]
fn add_is_full_data_delete_is_metadata() {
    let p=parse(container(&[operation(2,None,b"hello",b"hello")])).unwrap();
    assert_eq!(p.records[0].rec_type,RecordType::Add);
    assert_eq!(apply_record(&p,&p.records[0],None).unwrap(),Some(b"hello".to_vec()));
    assert!(apply_record(&p,&p.records[0],Some(b"wrong")).is_err());
    let p=parse(container(&[operation(3,Some(b"hello"),b"",b"")])).unwrap();
    assert_eq!(apply_record(&p,&p.records[0],Some(b"hello")).unwrap(),None);
    assert!(apply_record(&p,&p.records[0],Some(b"other")).is_err());
    assert_eq!(apply_record(&p,&p.records[0],None).unwrap(),None);
}
#[test]
fn history_selects_retail_intermediate_and_already_final() {
    let p=parse(container(&[history(&[transition(b"first",b"second",false), transition(b"second",b"last",true)])])).unwrap();
    let r=&p.records[0];assert!(r.children[1].src_entries[0].inherited);
    assert_eq!(r.children[1].src_entries[0].long_name.as_deref(),Some("x.txt"));
    for src in [b"first".as_slice(),b"second",b"last"] {assert_eq!(apply_record(&p,r,Some(src)).unwrap(),Some(b"last".to_vec()));}
    assert!(apply_record(&p,r,Some(b"FIRST")).is_err());assert!(apply_record(&p,r,None).is_err());
}
#[test]
fn history_delete_add_and_discarded_metadata() {
    let mut del=vec![];u16v(&mut del,0x2c3);del.push(1);entry(&mut del,b"old");
    let mut add=vec![];u16v(&mut add,0x2c2);body(&mut add,None,b"new",b"new",false);
    let p=parse(container(&[history(&[del.clone(),add])])).unwrap();
    for src in [Some(b"old".as_slice()),None] {assert_eq!(apply_record(&p,&p.records[0],src).unwrap(),Some(b"new".to_vec()));}
    let mut meta=del.clone();meta[..2].copy_from_slice(&0x243u16.to_le_bytes());
    let p=parse(container(&[history(&[meta,del])])).unwrap();
    assert_eq!(p.records[0].children[0].rec_type,RecordType::Metadata);
    assert_eq!(apply_record(&p,&p.records[0],Some(b"old")).unwrap(),None);
}
#[test]
fn rejects_bad_framing_inheritance_and_accumulators() {
    let good=container(&[history(&[transition(b"first",b"second",false),transition(b"second",b"last",true)])]);
    for n in [0,3,39,good.len()-1] {assert!(parse(good[..n].to_vec()).is_err());}
    let mut bad=good.clone();bad.push(0);assert!(parse(bad).is_err());
    let mut bad=good.clone();bad[30]=2;assert!(parse(bad).is_err());
    let mut c=transition(b"second",b"last",true);c[13]^=1;
    assert!(parse(container(&[history(&[transition(b"first",b"second",false),c])])).is_err());
    let mut c=transition(b"first",b"second",false);c[38]^=1;
    assert!(parse(container(&[history(&[c])])).is_err());
    let mut h=history(&[transition(b"first",b"second",false)]);h[22]=0xff;
    assert!(parse(container(&[h])).is_err());
}
#[test]
fn exact_codec_requires_size_terminator_and_padding() {
    for data in [b"".as_slice(),b"synthetic data"] {
        let c=compressed(data);assert_eq!(rtptool::codec::decompress_exact(&c,0,c.len(),data.len()).unwrap(),data);
        assert!(rtptool::codec::decompress_exact(&c,0,c.len(),data.len()+1).is_err());
        assert!(rtptool::codec::decompress_exact(&c,0,c.len()-1,data.len()).is_err());
        let mut bad=c.clone();bad.push(0);assert!(rtptool::codec::decompress_exact(&bad,0,bad.len(),data.len()).is_err());
        if !data.is_empty(){assert!(rtptool::codec::decompress_exact(&c,0,c.len(),data.len()-1).is_err());}
    }
    assert!(rtptool::codec::decompress_exact(&[],usize::MAX,2,0).is_err());
}
#[test]
fn both_checksums_and_destination_are_mandatory() {
    let mut p=parse(container(&[operation(4,Some(b"old"),b"new",b"\x05new\x01")])).unwrap();
    for which in 0..2 {
        let mut r=p.records[0].clone();if which==0 {r.src_entries[0].w1^=1;} else {r.src_entries[0].w2^=1;}
        assert!(apply_record(&p,&r,Some(b"old")).is_err());
    }
    p.records[0].dst_entries[0].w1^=1;
    assert!(apply_record(&p,&p.records[0],Some(b"old")).is_err());
}
#[test]
fn strict_opcodes_copy_templates_gaps_fills_and_pokes() {
    let run=|s:&[u8],p:&[u8],n|rtptool::apply::apply_exact(s,p,n).unwrap();
    assert_eq!(run(b"abcd",&[8,1,2,10,1,0,5,b'!',1],3),b"!bc");
    assert_eq!(run(b"abcd",&[4,1,1,2,5,b'!',b'?',1],4),b"!bc?");
    assert_eq!(run(b"",&[0x11,b'x',3,1],3),b"xxx");
    assert_eq!(run(b"",&[0x12,b'x',b'y',5,1],5),b"xyxyx");
    assert_eq!(run(b"",&[0x13,1,2,3,4,5,1],5),[1,2,3,4,1]);
    assert_eq!(run(b"",&[0x0c,1,2,5,b'x',1],3),[b'x',0,0]);
    assert_eq!(run(b"",&[0x14,1,b'x',2,5,b'y',1],3),b"yxx");
    assert_eq!(run(b"ab",&[3,0,2,0x0d,2,0,1,1,1,1],2),b"bc");
    assert_eq!(run(b"ab",&[3,0,2,6,1,1,1],2),b"ac");
    assert_eq!(run(b"ab",&[3,0,2,7,1,2,0,1,1],2),b"bc");
}
#[test]
fn strict_opcodes_reject_invalid_ranges_sources_and_missing_end() {
    for p in [&[3,0,4,1][..], &[3,0x81,1,1], &[0x11,0,4,1], &[6,0x81,1,1], &[9,0,1], &[2,1,1], &[5,0], &[4,1,0,1,1], &[1,0], &[]] {
        assert!(rtptool::apply::apply_exact(b"abc",p,3).is_err(),"{p:?}");
    }
}
#[test]
fn legacy_0209_layout_and_apply_remain_available() {
    let mut raw=container(&[operation(4,Some(b"old"),b"new",b"\x05new\x01")]);
    raw[2..4].copy_from_slice(&0x0209u16.to_le_bytes());raw.drain(20..24);
    let p=parse(raw).unwrap();assert_eq!(p.header.version,0x0209);
    assert_eq!(rtptool::patch_file(&p,&p.records[0],b"old",true).unwrap(),b"new");
    // Legacy clipping/growing remains separate from strict application.
    assert_eq!(rtptool::apply::apply(b"a",&[3,0,3,1],3,1).unwrap(),[b'a',0,0]);
}

#[test]
fn synthetic_covers_unobserved_poke_widths_and_fill_gaps() {
    let run=|p:&[u8],n|rtptool::apply::apply_exact(&[],p,n).unwrap();
    assert_eq!(run(&[0x0b,2,0x0e,1,2,0,1,1],2),[1,1]);
    assert_eq!(run(&[0x0b,4,0x0f,1,0,2,0,2,1],4),[1,0,1,0]);
    assert_eq!(run(&[0x0b,4,0x10,1,0,0,0,1,0,1],4),[1,0,0,0]);
    assert_eq!(run(&[0x15,1,1,2,3,5,9,1],4),[9,1,2,1]);
    assert_eq!(run(&[0x16,1,1,2,3,4,5,5,9,1],6),[9,1,2,3,4,1]);
    // Rewinding the output cursor must clear previously written data on zero fill.
    assert_eq!(run(&[0x11,7,2,2,0,0x0b,2,1],2),[0,0]);
}

#[test]
#[cfg(feature = "cli")]
fn cli_delete_out_file_cannot_remove_source_input() {
    let unique = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let root = std::env::temp_dir().join(format!("rtptool-synthetic-{}-{unique}", std::process::id()));
    let source = root.join("source");
    let input = source.join("dir/x.txt");
    std::fs::create_dir_all(input.parent().unwrap()).unwrap();
    std::fs::write(&input, b"hello").unwrap();
    let patch = root.join("synthetic.rtp");
    std::fs::write(&patch, container(&[operation(3, Some(b"hello"), b"", b"")])).unwrap();
    let result = std::process::Command::new(env!("CARGO_BIN_EXE_rtptool"))
        .arg("apply").arg(&patch).arg("--source").arg(&source)
        .arg("--output").arg(root.join("stage")).arg("--out-file").arg(&input)
        .output().unwrap();
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("would remove an input"));
    assert_eq!(std::fs::read(&input).unwrap(), b"hello");
    std::fs::remove_dir_all(root).unwrap();
}
