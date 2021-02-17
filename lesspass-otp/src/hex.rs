const HEX: &[u8] = b"0123456789abcdef";

pub fn to_hex(num: u32) -> Vec<u8> {
    if num < 16 {
        let mut h = Vec::with_capacity(1);
        h.push(HEX[num as usize]);
        h
    } else {
        let mut h = hex(num);
        while h[0] == HEX[0] {
            h.remove(0);
        }
        h
    }
}

fn hex(num: u32) -> Vec<u8> {
    let mut ret = Vec::new();

    {
        let i = num & 0b1111_1111;
        ret.push(HEX[((i & 0b1111_0000) >> 4) as usize]);
        ret.push(HEX[(i & 0b0000_1111) as usize]);
    }

    let num = num >> 8;
    if num > 0 {
        let mut other = hex(num);
        other.append(&mut ret);
        other
    } else {
        ret
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_11() {
        assert_eq!(to_hex(11), vec![HEX[11]])
    }

    #[test]
    fn hex_90() {
        assert_eq!(to_hex(90), vec![HEX[5], HEX[10]])
    }

    #[test]
    fn hex_2_032() {
        assert_eq!(to_hex(2_032), vec![HEX[7], HEX[15], HEX[0]]);
    }

    #[test]
    fn hex_59_905() {
        assert_eq!(to_hex(59_905), vec![HEX[14], HEX[10], HEX[0], HEX[1]]);
    }

    #[test]
    fn hex_60_000() {
        assert_eq!(to_hex(60_000), vec![HEX[14], HEX[10], HEX[6], HEX[0]]);
    }
}
