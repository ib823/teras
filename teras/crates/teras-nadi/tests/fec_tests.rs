//! Additional FEC tests.

use teras_nadi::fec::*;
use teras_nadi::*;

#[test]
fn test_fec_config_critical_priority() {
    let config = FecConfig::for_priority(Priority::Critical).unwrap();
    assert_eq!(config.data_shards, 4);
    assert_eq!(config.parity_shards, 1);
    assert_eq!(config.redundancy_percent(), 25.0);
}

#[test]
fn test_fec_config_high_priority() {
    let config = FecConfig::for_priority(Priority::VeryHigh).unwrap();
    assert_eq!(config.data_shards, 6);
    assert_eq!(config.parity_shards, 1);
}

#[test]
fn test_fec_config_no_fec_for_low() {
    assert!(FecConfig::for_priority(Priority::Background).is_none());
    assert!(FecConfig::for_priority(Priority::Low).is_none());
    assert!(FecConfig::for_priority(Priority::Normal).is_none());
}

#[test]
fn test_fec_encoder_creation() {
    let config = FecConfig {
        data_shards: 4,
        parity_shards: 2,
    };
    let encoder = ReedSolomonEncoder::new(config).unwrap();
    assert_eq!(encoder.config().total_shards(), 6);
}

#[test]
fn test_fec_decoder_creation() {
    let config = FecConfig {
        data_shards: 4,
        parity_shards: 2,
    };
    let decoder = ReedSolomonDecoder::new(config);
    assert_eq!(decoder.config().required_shards(), 4);
}
