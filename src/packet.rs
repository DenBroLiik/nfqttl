pub fn set_ipv4_ttl(packet: &mut [u8], ttl: u8) -> bool {
    if packet.len() < 20 || packet[0] >> 4 != 4 || ttl == 0 { return false; }
    let ihl = ((packet[0] & 0x0f) as usize) * 4;
    let total = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    if ihl < 20 || ihl > packet.len() || total < ihl || total > packet.len() { return false; }
    if packet[8] == ttl { return false; }
    packet[8] = ttl;
    packet[10] = 0;
    packet[11] = 0;
    let mut sum: u32 = 0;
    for i in (0..ihl).step_by(2) {
        sum += u16::from_be_bytes([packet[i], packet[i + 1]]) as u32;
    }
    while sum >> 16 != 0 { sum = (sum & 0xffff) + (sum >> 16); }
    let csum = !(sum as u16);
    let bytes = csum.to_be_bytes();
    packet[10] = bytes[0];
    packet[11] = bytes[1];
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn checksum(p: &[u8], ihl: usize) -> u16 {
        let mut sum = 0u32;
        for i in (0..ihl).step_by(2) { sum += u16::from_be_bytes([p[i], p[i + 1]]) as u32; }
        while sum >> 16 != 0 { sum = (sum & 0xffff) + (sum >> 16); }
        !(sum as u16)
    }
    fn packet(ihl_words: u8, ttl: u8) -> Vec<u8> {
        let ihl = ihl_words as usize * 4;
        let mut p = vec![0u8; ihl.max(64)];
        p[0] = 0x40 | ihl_words;
        let len = p.len() as u16;
        p[2..4].copy_from_slice(&len.to_be_bytes());
        p[8] = ttl;
        p[9] = 6;
        let mut sum = 0u32;
        for i in (0..ihl).step_by(2) { sum += u16::from_be_bytes([p[i], p[i + 1]]) as u32; }
        while sum >> 16 != 0 { sum = (sum & 0xffff) + (sum >> 16); }
        p[10..12].copy_from_slice(&(!(sum as u16)).to_be_bytes());
        p
    }

    #[test]
    fn ttl_and_checksum() {
        for ihl in 5..=15 {
            for ttl in 1..=255u8 {
                let mut p = packet(ihl, ttl);
                let changed = set_ipv4_ttl(&mut p, 64);
                assert_eq!(changed, ttl != 64);
                assert_eq!(p[8], 64);
                assert_eq!(checksum(&p, ihl as usize * 4), 0);
            }
        }
    }

    #[test]
    fn rejects_bad_packets() {
        let mut p = vec![0u8; 19];
        assert!(!set_ipv4_ttl(&mut p, 64));
        let mut p = packet(5, 63); p[0] = 0x65;
        assert!(!set_ipv4_ttl(&mut p, 64));
        let mut p = packet(5, 63); p[2..4].copy_from_slice(&4096u16.to_be_bytes());
        assert!(!set_ipv4_ttl(&mut p, 64));
    }
}
