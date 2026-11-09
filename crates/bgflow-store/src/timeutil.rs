//! Minimal civil-time conversion (Howard Hinnant's algorithm), used for
//! time-partitioned segment paths. Avoids pulling in chrono.

/// Break a unix-ms timestamp into (year, month, day, hour) UTC.
pub fn ymd_h_from_ms(ms: u64) -> (i64, u32, u32, u32) {
    let days = (ms / 86_400_000) as i64;
    let secs_of_day = (ms % 86_400_000) / 1000;
    let hour = (secs_of_day / 3600) as u32;

    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let mut y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    if m <= 2 {
        y += 1;
    }
    (y, m, d, hour)
}

/// Minute-aligned unix ms for a timestamp.
pub fn minute_floor(ms: u64) -> u64 {
    ms - (ms % 60_000)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_dates() {
        // 2024-01-01T00:00:00Z = 1704067200000
        assert_eq!(ymd_h_from_ms(1_704_067_200_000), (2024, 1, 1, 0));
        // 2024-03-01T12:00:00Z = 1709294400000
        assert_eq!(ymd_h_from_ms(1_709_294_400_000), (2024, 3, 1, 12));
        // leap day 2024-02-29T23:59:00Z = 1709251140000
        assert_eq!(ymd_h_from_ms(1_709_251_140_000), (2024, 2, 29, 23));
        // 1970-01-01
        assert_eq!(ymd_h_from_ms(0), (1970, 1, 1, 0));
    }
}
