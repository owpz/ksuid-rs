use crate::Ksuid;

/// Sort a slice of KSUIDs in ascending order (in-place).
pub fn sort(ids: &mut [Ksuid]) {
    ids.sort();
}

/// Returns true if the slice of KSUIDs is sorted in ascending order.
pub fn is_sorted(ids: &[Ksuid]) -> bool {
    ids.windows(2).all(|w| w[0] <= w[1])
}

/// Compare two KSUIDs, returning an Ordering.
///
/// This is equivalent to `a.cmp(&b)` but provided as a free function
/// for use as a comparator callback.
pub fn compare(a: &Ksuid, b: &Ksuid) -> core::cmp::Ordering {
    a.cmp(b)
}
