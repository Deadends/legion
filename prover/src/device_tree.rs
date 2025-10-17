use pasta_curves::Fp;
use ff::PrimeField;
use halo2_gadgets::poseidon::primitives as poseidon;
use anyhow::{Result, anyhow};
use std::collections::HashMap;
use std::sync::{RwLock, Arc};

const WIDTH: usize = 3;
const RATE: usize = 2;
pub const DEVICE_TREE_DEPTH: usize = 10; // 2^10 = 1024 devices per user

/// Per-user device Merkle tree for ring signatures
pub struct DeviceTree {
    devices: Vec<Fp>,
    tree: Vec<Vec<Fp>>,
}

impl DeviceTree {
    pub fn new() -> Self {
        Self {
            devices: Vec::new(),
            tree: vec![Vec::new(); DEVICE_TREE_DEPTH + 1],
        }
    }
    
    /// Add device commitment to tree
    pub fn add_device(&mut self, device_commitment: Fp) -> Result<usize> {
        let position = self.devices.len();
        self.devices.push(device_commitment);
        self.rebuild_tree();
        Ok(position)
    }
    
    /// Get Merkle proof for device at position
    pub fn get_proof(&self, position: usize) -> Result<([Fp; DEVICE_TREE_DEPTH], Fp)> {
        if position >= self.devices.len() {
            return Err(anyhow!("Device position out of bounds"));
        }
        
        let mut path = [Fp::zero(); DEVICE_TREE_DEPTH];
        let mut current_pos = position;
        
        for level in 0..DEVICE_TREE_DEPTH {
            let sibling_pos = current_pos ^ 1;
            path[level] = self.tree[level].get(sibling_pos).copied().unwrap_or(Fp::zero());
            current_pos >>= 1;
        }
        
        let root = self.get_root();
        Ok((path, root))
    }
    
    /// Get current root
    pub fn get_root(&self) -> Fp {
        self.tree[DEVICE_TREE_DEPTH].first().copied().unwrap_or(Fp::zero())
    }
    
    /// Get device count
    pub fn device_count(&self) -> usize {
        self.devices.len()
    }
    
    /// Rebuild tree after adding device
    fn rebuild_tree(&mut self) {
        // Level 0: leaves
        self.tree[0] = self.devices.clone();
        
        // Build up the tree
        for level in 0..DEVICE_TREE_DEPTH {
            let current_level = &self.tree[level];
            let mut next_level = Vec::new();
            
            for i in (0..current_level.len()).step_by(2) {
                let left = current_level[i];
                let right = current_level.get(i + 1).copied().unwrap_or(Fp::zero());
                
                let parent = poseidon::Hash::<_, poseidon::P128Pow5T3, poseidon::ConstantLength<2>, WIDTH, RATE>::init()
                    .hash([left, right]);
                next_level.push(parent);
            }
            
            if next_level.is_empty() {
                next_level.push(Fp::zero());
            }
            
            self.tree[level + 1] = next_level;
        }
    }
}

/// Global device tree manager (indexed by nullifier hash)
pub struct DeviceTreeManager {
    trees: Arc<RwLock<HashMap<String, DeviceTree>>>,
}

impl DeviceTreeManager {
    pub fn new() -> Self {
        Self {
            trees: Arc::new(RwLock::new(HashMap::new())),
        }
    }
    
    /// Register device for user (identified by nullifier hash)
    pub fn register_device(&self, nullifier_hash: &str, device_commitment: Fp) -> Result<(usize, Fp)> {
        let mut trees = self.trees.write().unwrap();
        let tree = trees.entry(nullifier_hash.to_string()).or_insert_with(DeviceTree::new);
        
        let position = tree.add_device(device_commitment)?;
        let root = tree.get_root();
        
        Ok((position, root))
    }
    
    /// Get device proof for user
    pub fn get_device_proof(&self, nullifier_hash: &str, position: usize) -> Result<([Fp; DEVICE_TREE_DEPTH], Fp)> {
        let trees = self.trees.read().unwrap();
        let tree = trees.get(nullifier_hash)
            .ok_or_else(|| anyhow!("No devices registered for this user"))?;
        
        tree.get_proof(position)
    }
    
    /// Get device tree root for user
    pub fn get_device_root(&self, nullifier_hash: &str) -> Result<Fp> {
        let trees = self.trees.read().unwrap();
        let tree = trees.get(nullifier_hash)
            .ok_or_else(|| anyhow!("No devices registered for this user"))?;
        
        Ok(tree.get_root())
    }
    
    /// Get device count for user
    pub fn get_device_count(&self, nullifier_hash: &str) -> usize {
        let trees = self.trees.read().unwrap();
        trees.get(nullifier_hash).map(|t| t.device_count()).unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_device_tree() {
        let mut tree = DeviceTree::new();
        
        let device1 = Fp::from(100u64);
        let device2 = Fp::from(200u64);
        
        let pos1 = tree.add_device(device1).unwrap();
        let pos2 = tree.add_device(device2).unwrap();
        
        assert_eq!(pos1, 0);
        assert_eq!(pos2, 1);
        assert_eq!(tree.device_count(), 2);
        
        let (path1, root1) = tree.get_proof(pos1).unwrap();
        let (path2, root2) = tree.get_proof(pos2).unwrap();
        
        assert_eq!(root1, root2);
        assert_ne!(path1[0], path2[0]); // Different siblings
    }
}
