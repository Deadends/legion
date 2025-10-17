use std::sync::atomic::{AtomicU64, Ordering};
use anyhow::{Result, Context};
use tracing::{info, warn, error, debug};

pub const NONCE_SIZE: usize = 12;

#[derive(Debug, Clone, Copy)]
pub struct NonceState {
    pub epoch: u32,
    pub sequence: u64,
    pub direction: Direction,
}

#[derive(Debug)]
pub struct NonceGenerator {
    state: AtomicU64, // Pack epoch(32) + sequence(32) into single atomic
    direction: Direction,
}

const EPOCH_SHIFT: u64 = 32;
const SEQUENCE_MASK: u64 = (1u64 << 32) - 1;

#[derive(Debug, Clone, Copy)]
pub enum Direction {
    ClientToServer = 0x01,
    ServerToClient = 0x02,
}

impl NonceGenerator {
    pub fn new(epoch: u32, direction: Direction) -> Self {
        let packed = ((epoch as u64) << EPOCH_SHIFT) | 0u64;
        Self {
            state: AtomicU64::new(packed),
            direction,
        }
    }

    pub fn next_nonce(&self) -> Result<[u8; NONCE_SIZE]> {
        let old_state = self.state.fetch_add(1, Ordering::SeqCst);
        let sequence = old_state & SEQUENCE_MASK;
        let epoch = (old_state >> EPOCH_SHIFT) as u32;
        
        // Check for sequence overflow
        if sequence >= (1u32 << 28) as u64 - 1 {
            return Err(anyhow::anyhow!("Sequence overflow - epoch rotation required"));
        }

        let mut nonce = [0u8; NONCE_SIZE];
        nonce[0..4].copy_from_slice(&epoch.to_le_bytes());
        nonce[4..11].copy_from_slice(&sequence.to_le_bytes()[..7]);
        nonce[11] = self.direction as u8;
        
        debug!("Generated nonce for epoch {} sequence {} direction {:?}", epoch, sequence, self.direction);
        Ok(nonce)
    }

    pub fn current_state(&self) -> NonceState {
        let state = self.state.load(Ordering::SeqCst);
        NonceState {
            epoch: (state >> EPOCH_SHIFT) as u32,
            sequence: state & SEQUENCE_MASK,
            direction: self.direction,
        }
    }

    pub fn rotate_epoch(&self) -> u32 {
        let old_state = self.state.load(Ordering::SeqCst);
        let old_epoch = (old_state >> EPOCH_SHIFT) as u32;
        let new_epoch = old_epoch.wrapping_add(1);
        let new_state = (new_epoch as u64) << EPOCH_SHIFT;
        
        self.state.store(new_state, Ordering::SeqCst);
        
        info!("Rotated nonce epoch from {} to {}", old_epoch, new_epoch);
        new_epoch
    }
    
    pub fn validate_nonce(&self, nonce: &[u8; NONCE_SIZE]) -> Result<NonceState> {
        if nonce.len() != NONCE_SIZE {
            return Err(anyhow::anyhow!("Invalid nonce size"));
        }
        
        let epoch = u32::from_le_bytes([nonce[0], nonce[1], nonce[2], nonce[3]]);
        
        let mut sequence_bytes = [0u8; 8];
        sequence_bytes[..7].copy_from_slice(&nonce[4..11]);
        let sequence = u64::from_le_bytes(sequence_bytes);
        
        let direction_byte = nonce[11];
        let direction = match direction_byte {
            0x01 => Direction::ClientToServer,
            0x02 => Direction::ServerToClient,
            _ => return Err(anyhow::anyhow!("Invalid direction in nonce")),
        };
        
        // Validate epoch is current or recent
        let current_state = self.current_state();
        if epoch > current_state.epoch || (current_state.epoch - epoch) > 2 {
            return Err(anyhow::anyhow!("Nonce epoch out of valid range"));
        }
        
        // Validate sequence number
        if sequence >= (1u32 << 28) as u64 {
            return Err(anyhow::anyhow!("Sequence number too large"));
        }
        
        Ok(NonceState {
            epoch,
            sequence,
            direction,
        })
    }
    
    pub fn get_statistics(&self) -> NonceStatistics {
        let state = self.current_state();
        NonceStatistics {
            current_epoch: state.epoch,
            current_sequence: state.sequence,
            direction: state.direction,
            total_nonces_generated: state.sequence,
        }
    }
}

#[derive(Debug, Clone)]
pub struct NonceStatistics {
    pub current_epoch: u32,
    pub current_sequence: u64,
    pub direction: Direction,
    pub total_nonces_generated: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nonce_generation() -> Result<()> {
        let gen = NonceGenerator::new(1, Direction::ClientToServer);
        
        let nonce1 = gen.next_nonce()?;
        let nonce2 = gen.next_nonce()?;
        
        // Nonces must be different
        assert_ne!(nonce1, nonce2);
        
        // Check format: epoch=1, seq=0, direction=0x01
        assert_eq!(&nonce1[0..4], &1u32.to_le_bytes());
        assert_eq!(&nonce1[4..11], &0u64.to_le_bytes()[..7]);
        assert_eq!(nonce1[11], 0x01);
        
        // Second nonce should have seq=1
        assert_eq!(&nonce2[4..11], &1u64.to_le_bytes()[..7]);
        
        Ok(())
    }

    #[test]
    fn test_epoch_rotation() -> Result<()> {
        let gen = NonceGenerator::new(1, Direction::ServerToClient);
        
        let _nonce1 = gen.next_nonce()?;
        assert_eq!(gen.current_state().sequence, 1);
        
        let new_epoch = gen.rotate_epoch();
        assert_eq!(new_epoch, 2);
        assert_eq!(gen.current_state().sequence, 0);
        
        let nonce_after_rotation = gen.next_nonce()?;
        assert_eq!(&nonce_after_rotation[0..4], &2u32.to_le_bytes());
        assert_eq!(&nonce_after_rotation[4..11], &0u64.to_le_bytes()[..7]);
        
        Ok(())
    }
    
    #[test]
    fn test_nonce_validation() -> Result<()> {
        let gen = NonceGenerator::new(5, Direction::ClientToServer);
        
        let nonce = gen.next_nonce()?;
        let state = gen.validate_nonce(&nonce)?;
        
        assert_eq!(state.epoch, 5);
        assert_eq!(state.sequence, 0);
        assert!(matches!(state.direction, Direction::ClientToServer));
        
        Ok(())
    }
}