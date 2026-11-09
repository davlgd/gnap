//! A registry value crosses the wire unaltered, registered or not.

use gnap_registry::KeyProofingMethod;

#[test]
fn registered_and_unregistered_values_round_trip_unaltered() {
    for wire in [r#""httpsig""#, r#""quantum-sig""#] {
        let value: KeyProofingMethod = serde_json::from_str(wire).unwrap();
        assert_eq!(serde_json::to_string(&value).unwrap(), wire);
    }
    let unknown: KeyProofingMethod = serde_json::from_str(r#""quantum-sig""#).unwrap();
    assert!(!unknown.is_registered());
}

#[test]
fn a_registry_value_must_be_a_string() {
    assert!(serde_json::from_str::<KeyProofingMethod>("42").is_err());
}
