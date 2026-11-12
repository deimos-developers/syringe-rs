//! Translation of `SyringeEx/CRC32.cpp` and `SyringeEx/CRC32.h`.

const fn create_crc_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0u32;

    while i < 256 {
        let mut value = i;
        let mut j = 8u32;

        while j != 0 {
            // bit-reverse 0x04C11DB7U
            let polynomial = if value & 1 != 0 { 0xEDB8_8320u32 } else { 0 };
            value = (value >> 1) ^ polynomial;
            j -= 1;
        }

        table[i as usize] = value;
        i += 1;
    }

    table
}

pub struct Crc32 {
    value: u32,
}

impl Default for Crc32 {
    fn default() -> Self {
        Self::new()
    }
}

impl Crc32 {
    pub const fn new() -> Self {
        Self { value: 0xFFFF_FFFF }
    }

    pub fn compute(&mut self, buffer: &[u8]) -> u32 {
        static CRC_TABLE: [u32; 256] = create_crc_table();

        for &byte in buffer {
            let index = ((self.value & 0xFF) ^ byte as u32) as u8;
            self.value = (self.value >> 8) ^ CRC_TABLE[index as usize];
        }

        !self.value
    }

    pub fn value(&self) -> u32 {
        !self.value
    }

    pub fn reset(&mut self) {
        self.value = 0xFFFF_FFFF;
    }
}

#[cfg(test)]
mod tests {
    use super::Crc32;

    #[test]
    fn known_crc32_vectors() {
        let mut crc = Crc32::new();
        assert_eq!(crc.compute(b""), 0);
        assert_eq!(crc.value(), 0);
        crc.reset();
        assert_eq!(crc.compute(b"123456789"), 0xCBF4_3926);
    }

    #[test]
    fn chained_computation_matches_one_shot() {
        let mut chained = Crc32::new();
        chained.compute(b"1234");
        let chained = chained.compute(b"56789");
        let mut one_shot = Crc32::new();
        assert_eq!(chained, one_shot.compute(b"123456789"));
    }
}
