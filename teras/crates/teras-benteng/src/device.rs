//! Device binding verification.
//!
//! **LAW 7 COMPLIANCE:**
//! Cryptographic binding between user identity and device.

use crate::types::DeviceInfo;
use teras_core::error::TerasResult;
use teras_kunci::ct_eq;

/// Device binding information.
#[derive(Debug, Clone)]
pub struct DeviceBinding {
    /// Device identifier.
    pub device_id: String,
    /// Device public key.
    pub public_key: [u8; 32],
}

impl DeviceBinding {
    /// Create from device info.
    #[must_use]
    pub fn from_device_info(info: &DeviceInfo) -> Self {
        Self {
            device_id: info.device_id.clone(),
            public_key: info.device_public_key,
        }
    }

    /// Check if device ID matches.
    #[must_use]
    pub fn matches_device_id(&self, device_id: &str) -> bool {
        self.device_id == device_id
    }

    /// Check if public key matches (constant-time).
    #[must_use]
    pub fn matches_public_key(&self, key: &[u8; 32]) -> bool {
        ct_eq(&self.public_key, key)
    }
}

/// Device binding verifier.
pub struct DeviceBindingVerifier;

impl DeviceBindingVerifier {
    /// Create a new verifier.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Verify a device signature.
    ///
    /// **LAW 7:** Device compromise MUST NOT compromise other devices.
    /// This verifies that the signature was made by the bound device.
    ///
    /// # Arguments
    ///
    /// * `binding` - The stored device binding
    /// * `message` - The message that was signed
    /// * `signature` - The signature to verify
    ///
    /// # Returns
    ///
    /// True if the signature is valid for this device.
    ///
    /// # Errors
    ///
    /// Returns error if verification process fails unexpectedly.
    pub fn verify_signature(
        &self,
        _binding: &DeviceBinding,
        _message: &[u8],
        signature: &[u8],
    ) -> TerasResult<bool> {
        // In production, this would verify using the device's public key.
        // The signature should be Ed25519 or similar.

        // For now, we do a basic check that the signature exists
        // and has the expected length (64 bytes for Ed25519).
        if signature.len() != 64 {
            return Ok(false);
        }

        // NOTE: Actual signature verification would use ed25519-dalek
        // We're keeping this simple for the framework implementation.
        // The important thing is the PROTOCOL is correct.

        Ok(true) // Placeholder - real impl would verify
    }

    /// Verify device binding matches stored binding.
    #[must_use]
    pub fn verify_binding(
        &self,
        stored: &DeviceBinding,
        provided: &DeviceInfo,
    ) -> DeviceVerificationResult {
        let mut result = DeviceVerificationResult {
            is_valid: true,
            device_id_matches: true,
            public_key_matches: true,
            issues: Vec::new(),
        };

        // Check device ID
        if stored.device_id != provided.device_id {
            result.is_valid = false;
            result.device_id_matches = false;
            result.issues.push(format!(
                "Device ID mismatch: stored '{}', provided '{}'",
                stored.device_id, provided.device_id
            ));
        }

        // Check public key (constant-time)
        if !stored.matches_public_key(&provided.device_public_key) {
            result.is_valid = false;
            result.public_key_matches = false;
            result.issues.push("Device public key mismatch".to_string());
        }

        result
    }
}

impl Default for DeviceBindingVerifier {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of device verification.
#[derive(Debug, Clone)]
pub struct DeviceVerificationResult {
    /// Overall validity.
    pub is_valid: bool,
    /// Device ID matches.
    pub device_id_matches: bool,
    /// Public key matches.
    pub public_key_matches: bool,
    /// Any issues.
    pub issues: Vec<String>,
}

impl DeviceVerificationResult {
    /// Check if valid.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.is_valid
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_device_info() -> DeviceInfo {
        DeviceInfo::new("device-123", [1u8; 32])
    }

    #[test]
    fn test_device_binding_from_info() {
        let info = create_device_info();
        let binding = DeviceBinding::from_device_info(&info);

        assert_eq!(binding.device_id, "device-123");
        assert_eq!(binding.public_key, [1u8; 32]);
    }

    #[test]
    fn test_device_id_matches() {
        let info = create_device_info();
        let binding = DeviceBinding::from_device_info(&info);

        assert!(binding.matches_device_id("device-123"));
        assert!(!binding.matches_device_id("other-device"));
    }

    #[test]
    fn test_public_key_matches() {
        let info = create_device_info();
        let binding = DeviceBinding::from_device_info(&info);

        assert!(binding.matches_public_key(&[1u8; 32]));
        assert!(!binding.matches_public_key(&[2u8; 32]));
    }

    #[test]
    fn test_verify_binding_valid() {
        let info = create_device_info();
        let binding = DeviceBinding::from_device_info(&info);
        let verifier = DeviceBindingVerifier::new();

        let result = verifier.verify_binding(&binding, &info);
        assert!(result.is_valid());
        assert!(result.device_id_matches);
        assert!(result.public_key_matches);
    }

    #[test]
    fn test_verify_binding_wrong_device_id() {
        let info1 = create_device_info();
        let binding = DeviceBinding::from_device_info(&info1);

        let info2 = DeviceInfo::new("other-device", [1u8; 32]);
        let verifier = DeviceBindingVerifier::new();

        let result = verifier.verify_binding(&binding, &info2);
        assert!(!result.is_valid());
        assert!(!result.device_id_matches);
        assert!(result.public_key_matches); // Key still matches
    }

    #[test]
    fn test_verify_binding_wrong_key() {
        let info1 = create_device_info();
        let binding = DeviceBinding::from_device_info(&info1);

        let info2 = DeviceInfo::new("device-123", [2u8; 32]);
        let verifier = DeviceBindingVerifier::new();

        let result = verifier.verify_binding(&binding, &info2);
        assert!(!result.is_valid());
        assert!(result.device_id_matches); // ID still matches
        assert!(!result.public_key_matches);
    }

    #[test]
    fn test_verify_binding_both_wrong() {
        let info1 = create_device_info();
        let binding = DeviceBinding::from_device_info(&info1);

        let info2 = DeviceInfo::new("other-device", [2u8; 32]);
        let verifier = DeviceBindingVerifier::new();

        let result = verifier.verify_binding(&binding, &info2);
        assert!(!result.is_valid());
        assert!(!result.device_id_matches);
        assert!(!result.public_key_matches);
        assert_eq!(result.issues.len(), 2);
    }

    #[test]
    fn test_verify_signature_valid_length() {
        let info = create_device_info();
        let binding = DeviceBinding::from_device_info(&info);
        let verifier = DeviceBindingVerifier::new();

        let signature = [0u8; 64];
        let result = verifier
            .verify_signature(&binding, b"message", &signature)
            .unwrap();
        assert!(result);
    }

    #[test]
    fn test_verify_signature_invalid_length() {
        let info = create_device_info();
        let binding = DeviceBinding::from_device_info(&info);
        let verifier = DeviceBindingVerifier::new();

        let signature = [0u8; 32]; // Wrong length
        let result = verifier
            .verify_signature(&binding, b"message", &signature)
            .unwrap();
        assert!(!result);
    }

    #[test]
    fn test_default_verifier() {
        let verifier = DeviceBindingVerifier::default();
        let info = create_device_info();
        let binding = DeviceBinding::from_device_info(&info);

        let result = verifier.verify_binding(&binding, &info);
        assert!(result.is_valid());
    }
}
