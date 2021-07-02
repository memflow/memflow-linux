fn str_to_byte_iter<'a>(s: &'a str) -> impl 'a + Iterator<Item = u8> {
    s.split_whitespace()
        .map(|b| u8::from_str_radix(b, 16).unwrap_or(0))
}

fn str_to_mask_iter<'a>(s: &'a str) -> impl 'a + Iterator<Item = u8> {
    s.split_whitespace()
        .map(|b| if b.contains("?") { 0 } else { 0xff })
}

fn str_to_deref_pos_iter<'a>(s: &'a str, off: usize) -> (usize, impl 'a + Iterator<Item = usize>) {
    (
        off + s.split_whitespace().enumerate().count(),
        s.split_whitespace()
            .enumerate()
            .filter(|(_, b)| b.starts_with("*"))
            .map(move |(i, _)| i + off),
    )
}

#[derive(Clone)]
pub struct Signature {
    bytes: Vec<u8>,
    mask: Vec<u8>,
    pub deref_pos: Vec<usize>,
}

impl Signature {
    pub fn new(s: &[&str]) -> Self {
        let mut bytes = vec![];
        let mut mask = vec![];
        let mut deref_pos = vec![];

        let mut off = 0;

        for s in s {
            bytes.extend(str_to_byte_iter(s));
            mask.extend(str_to_mask_iter(s));
            let (o, i) = str_to_deref_pos_iter(s, off);
            off = o;
            deref_pos.extend(i);
        }

        Self {
            bytes,
            mask,
            deref_pos,
        }
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }
}

impl PartialEq<&[u8]> for Signature {
    fn eq(&self, other: &&[u8]) -> bool {
        if self.len() == other.len() {
            other
                .iter()
                .zip(&self.mask)
                .map(|(b, m)| b & m)
                .eq(self.bytes.iter().copied())
        } else {
            false
        }
    }
}

impl PartialEq<Signature> for &[u8] {
    fn eq(&self, other: &Signature) -> bool {
        other.eq(self)
    }
}
