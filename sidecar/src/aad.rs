use crate::nonce::Direction;

pub struct AadBuilder;

impl AadBuilder {

    pub fn build(
        session_id: &[u8; 32],
        epoch: u32,
        direction: Direction,
        transcript_hash: &[u8; 32],
        sequence: u64,
    ) -> Vec<u8> {
        let mut aad = Vec::with_capacity(80);
        
        // session_id (32 bytes)
        aad.extend_from_slice(session_id);
        
        // epoch (4 bytes, little-endian)
        aad.extend_from_slice(&epoch.to_le_bytes());
        
        // direction (3 bytes)
        let direction_str = match direction {
            Direction::ClientToServer => b"C2S",
            Direction::ServerToClient => b"S2C",
        };
        aad.extend_from_slice(direction_str);
        
        // transcript_hash (32 bytes)
        aad.extend_from_slice(transcript_hash);
        
        // sequence (8 bytes, little-endian)
        aad.extend_from_slice(&sequence.to_le_bytes());
        
        aad
    }

    pub fn validate_aad(
        aad: &[u8],
        expected_session_id: &[u8; 32],
        expected_epoch: u32,
        expected_direction: Direction,
        expected_transcript: &[u8; 32],
        expected_sequence: u64,
    ) -> Result<(), &'static str> {
        if aad.len() != 79 { // 32 + 4 + 3 + 32 + 8
            return Err("Invalid AAD length");
        }

        // Validate session_id
        if &aad[0..32] != expected_session_id {
            return Err("AAD session_id mismatch");
        }

        // Validate epoch
        let epoch_bytes = &aad[32..36];
        if u32::from_le_bytes([epoch_bytes[0], epoch_bytes[1], epoch_bytes[2], epoch_bytes[3]]) != expected_epoch {
            return Err("AAD epoch mismatch");
        }

        // Validate direction
        let direction_bytes = &aad[36..39];
        let expected_dir_str = match expected_direction {
            Direction::ClientToServer => b"C2S",
            Direction::ServerToClient => b"S2C",
        };
        if direction_bytes != expected_dir_str {
            return Err("AAD direction mismatch");
        }

        // Validate transcript_hash
        if &aad[39..71] != expected_transcript {
            return Err("AAD transcript mismatch");
        }

        // Validate sequence
        let seq_bytes = &aad[71..79];
        let seq_array: [u8; 8] = seq_bytes.try_into().map_err(|_| "Invalid sequence bytes")?;
        if u64::from_le_bytes(seq_array) != expected_sequence {
            return Err("AAD sequence mismatch");
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aad_construction() {
        let session_id = [0x01u8; 32];
        let epoch = 42u32;
        let direction = Direction::ClientToServer;
        let transcript = [0x02u8; 32];
        let sequence = 1337u64;

        let aad = AadBuilder::build(&session_id, epoch, direction, &transcript, sequence);
        
        assert_eq!(aad.len(), 79);
        
        // Verify components
        assert_eq!(&aad[0..32], &session_id);
        assert_eq!(&aad[32..36], &epoch.to_le_bytes());
        assert_eq!(&aad[36..39], b"C2S");
        assert_eq!(&aad[39..71], &transcript);
        assert_eq!(&aad[71..79], &sequence.to_le_bytes());
    }

    #[test]
    fn test_aad_validation() {
        let session_id = [0x01u8; 32];
        let epoch = 42u32;
        let direction = Direction::ServerToClient;
        let transcript = [0x02u8; 32];
        let sequence = 1337u64;

        let aad = AadBuilder::build(&session_id, epoch, direction, &transcript, sequence);
        
        // Valid AAD should pass
        assert!(AadBuilder::validate_aad(
            &aad, &session_id, epoch, direction, &transcript, sequence
        ).is_ok());
        
        // Wrong session_id should fail
        let wrong_session = [0x99u8; 32];
        assert!(AadBuilder::validate_aad(
            &aad, &wrong_session, epoch, direction, &transcript, sequence
        ).is_err());
        
        // Wrong epoch should fail
        assert!(AadBuilder::validate_aad(
            &aad, &session_id, epoch + 1, direction, &transcript, sequence
        ).is_err());
    }

    #[test]
    fn test_direction_encoding() {
        let session_id = [0x01u8; 32];
        let transcript = [0x02u8; 32];
        
        let aad_c2s = AadBuilder::build(&session_id, 0, Direction::ClientToServer, &transcript, 0);
        let aad_s2c = AadBuilder::build(&session_id, 0, Direction::ServerToClient, &transcript, 0);
        
        assert_eq!(&aad_c2s[36..39], b"C2S");
        assert_eq!(&aad_s2c[36..39], b"S2C");
        assert_ne!(aad_c2s, aad_s2c);
    }
}