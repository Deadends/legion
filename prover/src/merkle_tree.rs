use anyhow::Result;
use ff::PrimeField;
use halo2_gadgets::poseidon::primitives as poseidon;
use hex;
use pasta_curves::Fp;

#[cfg(feature = "rocksdb-storage")]
use crate::rocksdb_merkle::RocksDBMerkleTree;

const WIDTH: usize = 3;
const RATE: usize = 2;
const MERKLE_DEPTH: usize = 20;

/// Production Merkle tree with RocksDB backend
#[cfg(feature = "rocksdb-storage")]
pub struct AnonymityMerkleTree {
    rocksdb_tree: RocksDBMerkleTree,
}

#[cfg(not(feature = "rocksdb-storage"))]
pub struct AnonymityMerkleTree {}

impl AnonymityMerkleTree {
    #[cfg(feature = "rocksdb-storage")]
    pub fn new_with_rocksdb(db_path: &str) -> Result<Self> {
        let rocksdb_tree = RocksDBMerkleTree::new(db_path)?;
        Ok(Self { rocksdb_tree })
    }

    #[cfg(not(feature = "rocksdb-storage"))]
    pub fn new_with_rocksdb(_db_path: &str) -> Result<Self> {
        Ok(Self {})
    }

    #[cfg(feature = "rocksdb-storage")]
    pub fn add_leaf(&mut self, leaf: Fp) -> Result<usize> {
        self.rocksdb_tree.add_leaf(leaf)
    }

    #[cfg(not(feature = "rocksdb-storage"))]
    pub fn add_leaf(&mut self, _leaf: Fp) -> Result<usize> {
        Ok(0)
    }

    #[cfg(feature = "rocksdb-storage")]
    pub fn get_proof(&self, index: usize) -> Result<([Fp; MERKLE_DEPTH], Fp)> {
        self.rocksdb_tree.get_proof(index)
    }

    #[cfg(not(feature = "rocksdb-storage"))]
    pub fn get_proof(&self, _index: usize) -> Result<([Fp; MERKLE_DEPTH], Fp)> {
        Ok(([Fp::zero(); MERKLE_DEPTH], Fp::zero()))
    }

    #[cfg(feature = "rocksdb-storage")]
    pub fn get_anonymity_set_size(&self) -> usize {
        self.rocksdb_tree.get_anonymity_set_size()
    }

    #[cfg(not(feature = "rocksdb-storage"))]
    pub fn get_anonymity_set_size(&self) -> usize {
        0
    }

    #[cfg(feature = "rocksdb-storage")]
    pub fn get_root(&self) -> Fp {
        self.rocksdb_tree.get_root()
    }

    #[cfg(not(feature = "rocksdb-storage"))]
    pub fn get_root(&self) -> Fp {
        Fp::zero()
    }

    #[cfg(feature = "rocksdb-storage")]
    pub fn get_leaf_index(&self, leaf: &Fp) -> Option<usize> {
        self.rocksdb_tree.get_leaf_index(leaf)
    }

    #[cfg(not(feature = "rocksdb-storage"))]
    pub fn get_leaf_index(&self, _leaf: &Fp) -> Option<usize> {
        None
    }

    pub fn get_leaves(&self) -> Vec<Fp> {
        vec![]
    }

    pub fn get_all_paths(&self) -> Vec<Vec<String>> {
        let size = self.get_anonymity_set_size();
        (0..size)
            .map(|i| {
                let (path, _) = self
                    .get_proof(i)
                    .unwrap_or(([Fp::zero(); MERKLE_DEPTH], Fp::zero()));
                path.iter().map(|p| hex::encode(p.to_repr())).collect()
            })
            .collect()
    }
}

pub fn create_test_anonymity_set(
    user_leaf: Fp,
    min_size: usize,
) -> Result<(AnonymityMerkleTree, usize)> {
    let mut tree = AnonymityMerkleTree::new_with_rocksdb("./legion_data/rocksdb_merkle")?;

    let current_size = tree.get_anonymity_set_size();
    if current_size < min_size {
        for i in current_size..min_size.saturating_sub(1) {
            let dummy_leaf = poseidon::Hash::<
                _,
                poseidon::P128Pow5T3,
                poseidon::ConstantLength<1>,
                WIDTH,
                RATE,
            >::init()
            .hash([Fp::from(i as u64 + 1000)]);
            tree.add_leaf(dummy_leaf)?;
        }
    }

    let user_index = tree.add_leaf(user_leaf)?;
    Ok((tree, user_index))
}

pub fn get_global_anonymity_tree() -> Result<AnonymityMerkleTree> {
    AnonymityMerkleTree::new_with_rocksdb("./legion_data/rocksdb_merkle")
}

pub fn add_to_global_anonymity(user_leaf: Fp) -> Result<(usize, Fp)> {
    let mut tree = get_global_anonymity_tree()?;
    let index = tree.add_leaf(user_leaf)?;
    let root = tree.get_root();
    Ok((index, root))
}
