//! The two date formats mail sources use: RFC 2822 (`Date:` headers) and RFC 3339 (Mailpit's
//! `Created`). UTC civil-date math, no dependency.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

const MONTHS: [&str; 12] = [
    "jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec",
];

/// Days since 1970-01-01 for a proleptic Gregorian date (Howard Hinnant's algorithm).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

fn to_system(secs: i64, nanos: u32) -> Option<SystemTime> {
    let s = u64::try_from(secs).ok()?;
    UNIX_EPOCH.checked_add(Duration::new(s, nanos))
}

fn valid(y: i64, mo: i64, d: i64, h: i64, mi: i64, s: i64) -> bool {
    (1970..=9999).contains(&y)
        && (1..=12).contains(&mo)
        && (1..=31).contains(&d)
        && (0..24).contains(&h)
        && (0..60).contains(&mi)
        && (0..=60).contains(&s)
}

/// `2026-11-16T10:00:00.123Z` or `...+02:00`.
pub fn parse_rfc3339(s: &str) -> Option<SystemTime> {
    let s = s.trim();
    let (date, rest) = s.split_once(['T', 't', ' '])?;
    let mut dp = date.split('-');
    let (y, mo, d) = (
        dp.next()?.parse::<i64>().ok()?,
        dp.next()?.parse::<i64>().ok()?,
        dp.next()?.parse::<i64>().ok()?,
    );
    let tz_at = rest.find(['Z', 'z', '+', '-'])?;
    let (time, tz) = rest.split_at(tz_at);
    let (hms, frac) = time.split_once('.').unwrap_or((time, ""));
    let mut tp = hms.split(':');
    let (h, mi, sec) = (
        tp.next()?.parse::<i64>().ok()?,
        tp.next()?.parse::<i64>().ok()?,
        tp.next()?.parse::<i64>().ok()?,
    );
    if !valid(y, mo, d, h, mi, sec) {
        return None;
    }
    let nanos = if frac.is_empty() {
        0
    } else {
        let digits: String = frac.chars().take(9).collect();
        let n: u32 = digits.parse().ok()?;
        n * 10u32.pow(9 - u32::try_from(digits.len()).ok()?)
    };
    let offset = match tz {
        "Z" | "z" => 0,
        _ => {
            let sign = if tz.starts_with('-') { -1 } else { 1 };
            let (oh, om) = tz[1..].split_once(':')?;
            sign * (oh.parse::<i64>().ok()? * 3600 + om.parse::<i64>().ok()? * 60)
        }
    };
    let secs = days_from_civil(y, mo, d) * 86_400 + h * 3600 + mi * 60 + sec - offset;
    to_system(secs, nanos)
}

/// `Thu, 12 Nov 2026 00:00:00 +0000` (weekday optional, `GMT`/`UT`/`UTC` accepted).
pub fn parse_rfc2822(s: &str) -> Option<SystemTime> {
    let s = s.split_once(',').map_or(s, |(_, r)| r);
    let mut it = s.split_whitespace();
    let d: i64 = it.next()?.parse().ok()?;
    let mon = it.next()?.to_ascii_lowercase();
    let mo = MONTHS.iter().position(|m| mon.starts_with(m))? as i64 + 1;
    let y: i64 = it.next()?.parse().ok()?;
    let mut tp = it.next()?.split(':');
    let h: i64 = tp.next()?.parse().ok()?;
    let mi: i64 = tp.next()?.parse().ok()?;
    let sec: i64 = tp.next().map_or(Some(0), |v| v.parse().ok())?;
    if !valid(y, mo, d, h, mi, sec) {
        return None;
    }
    let tz = it.next().unwrap_or("+0000");
    let offset = match tz.to_ascii_uppercase().as_str() {
        "GMT" | "UT" | "UTC" | "Z" => 0,
        t if t.len() == 5 && (t.starts_with('+') || t.starts_with('-')) => {
            let sign = if t.starts_with('-') { -1 } else { 1 };
            let oh: i64 = t[1..3].parse().ok()?;
            let om: i64 = t[3..5].parse().ok()?;
            sign * (oh * 3600 + om * 60)
        }
        _ => 0,
    };
    let secs = days_from_civil(y, mo, d) * 86_400 + h * 3600 + mi * 60 + sec - offset;
    to_system(secs, 0)
}

/// RFC 2822 date in UTC for Unix seconds.
pub fn format_rfc2822(secs: u64) -> String {
    const DAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    const MON: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let days = secs / 86_400;
    let rem = secs % 86_400;
    let (y, m, d) = civil_from_days(i64::try_from(days).unwrap_or(0));
    format!(
        "{}, {:02} {} {} {:02}:{:02}:{:02} +0000",
        DAYS[(days % 7) as usize],
        d,
        MON[usize::try_from(m - 1).unwrap_or(0)],
        y,
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_and_rfc2822_agree() {
        let a = parse_rfc3339("2026-11-12T00:00:00Z").expect("3339");
        let b = parse_rfc2822("Thu, 12 Nov 2026 00:00:00 +0000").expect("2822");
        assert_eq!(a, b);
        assert_eq!(a, UNIX_EPOCH + Duration::from_secs(1_794_441_600));
        let c = parse_rfc3339("2026-11-12T02:00:00.5+02:00").expect("offset");
        assert_eq!(c, a + Duration::from_millis(500));
        assert_eq!(
            format_rfc2822(1_794_441_600),
            "Thu, 12 Nov 2026 00:00:00 +0000"
        );
        assert_eq!(
            parse_rfc2822(&format_rfc2822(1_794_441_601)),
            Some(UNIX_EPOCH + Duration::from_secs(1_794_441_601))
        );
        assert!(parse_rfc3339("not a date").is_none());
    }
}
