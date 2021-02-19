lazy_static! {
    static ref COLORS: [&'static str; 14] = [
        "#000000", "#074750", "#009191", "#FF6CB6", "#FFB5DA", "#490092", "#006CDB", "#B66DFF",
        "#6DB5FE", "#B5DAFE", "#920000", "#924900", "#DB6D00", "#24FE23"
    ];
    static ref ICONS: [&'static str; 46] = [
        "fa-hashtag",
        "fa-heart",
        "fa-hotel",
        "fa-university",
        "fa-plug",
        "fa-ambulance",
        "fa-bus",
        "fa-car",
        "fa-plane",
        "fa-rocket",
        "fa-ship",
        "fa-subway",
        "fa-truck",
        "fa-jpy",
        "fa-eur",
        "fa-btc",
        "fa-usd",
        "fa-gbp",
        "fa-archive",
        "fa-area-chart",
        "fa-bed",
        "fa-beer",
        "fa-bell",
        "fa-binoculars",
        "fa-birthday-cake",
        "fa-bomb",
        "fa-briefcase",
        "fa-bug",
        "fa-camera",
        "fa-cart-plus",
        "fa-certificate",
        "fa-coffee",
        "fa-cloud",
        "fa-coffee",
        "fa-comment",
        "fa-cube",
        "fa-cutlery",
        "fa-database",
        "fa-diamond",
        "fa-exclamation-circle",
        "fa-eye",
        "fa-flag",
        "fa-flask",
        "fa-futbol-o",
        "fa-gamepad",
        "fa-graduation-cap"
    ];
}

/// Return the color, based on string passed in parameters
fn get_color(color: &str) -> &'static str {
    let idx =
        u64::from_str_radix(color, 16).expect("color was not an hex value") as usize % COLORS.len();
    COLORS[idx]
}

/// Return an icon, based on string passed in parameters
fn get_icon(icon: &str) -> &'static str {
    let idx =
        u64::from_str_radix(icon, 16).expect("icon was not an hex value") as usize % ICONS.len();
    ICONS[idx]
}

/// Define a tuple representing an icon for the fingerprint: `(color, icon)`
type ColorIcon = (&'static str, &'static str);

/// Representation of the fingerprint.
///
/// This is a 3 array of tuples, which the first element is the color, the second an
/// icon from _font-awesome_.
///
/// This representation should be publicly displayed to the user to verify his
/// master password.
pub type Fingerprint = [ColorIcon; 3];

pub fn get_fingerprint(fingerprint: &str) -> Fingerprint {
    let hash1 = &fingerprint[0..6];
    let hash2 = &fingerprint[6..12];
    let hash3 = &fingerprint[12..18];

    [
        (get_color(hash1), get_icon(hash1)),
        (get_color(hash2), get_icon(hash2)),
        (get_color(hash3), get_icon(hash3)),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_internet() {
        assert_eq!(
            get_fingerprint("e56a207acd1e6714735487c199c6f095844b7cc8e5971d86c003a7b6f36ef51e"),
            [
                ("#FFB5DA", "fa-flask"),
                ("#009191", "fa-archive"),
                ("#B5DAFE", "fa-beer")
            ]
        );
    }
}
