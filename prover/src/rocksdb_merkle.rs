// Production-grade Merkle tree with RocksDB backend
// Used by Ethereum, Bitcoin - instant startup, scales to millions
use anyhow::{Context, Result};
use ff::PrimeField;
use halo2_gadgets::poseidon::primitives as poseidon;
use pasta_curves::Fp;
#[cfg(feature = "rocksdb-storage")]
use rocksdb::{Options, WriteBatch, DB};
use std::sync::{Arc, Mutex};

const WIDTH: usize = 3;
const RATE: usize = 2;
const MERKLE_DEPTH: usize = 20;

#[cfg(feature = "rocksdb-storage")]
pub struct RocksDBMerkleTree {
    db: Arc<Mutex<DB>>,
    next_index: usize,
}

#[cfg(feature = "rocksdb-storage")]
impl RocksDBMerkleTree {
    pub fn new(db_path: &str) -> Result<Self> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.set_compression_type(rocksdb::DBCompressionType::Lz4);

        let db = DB::open(&opts, db_path).context("Failed to open RocksDB")?;

        let next_index = db
            .get(b"meta:next_index")?
            .and_then(|bytes| {
                if bytes.len() == 8 {
                    let mut arr = [0u8; 8];
                    arr.copy_from_slice(&bytes);
                    Some(usize::from_le_bytes(arr))
                } else {
                    None
                }
            })
            .unwrap_or(0);

        Ok(Self {
            db: Arc::new(Mutex::new(db)),
            next_index,
        })
    }

    pub fn add_leaf(&mut self, leaf: Fp) -> Result<usize> {
        let index = self.next_index;
        let batch = {
            let db = self.db.lock().unwrap();
            let mut batch = WriteBatch::default();

            // Store leaf
            let leaf_key = format!("leaf:{}", index);
            let leaf_repr = leaf.to_repr();
            let leaf_bytes: &[u8] = leaf_repr.as_ref();
            batch.put(leaf_key.as_bytes(), leaf_bytes);

            // Update path to root
            self.update_path_batch(&db, &mut batch, index, leaf)?;

            // Update metadata
            batch.put(b"meta:next_index", &(index + 1).to_le_bytes());
            batch
        }; // Lock released here

        // Write batch (quick operation)
        self.db.lock().unwrap().write(batch)?;
        self.next_index += 1;
        Ok(index)
    }

    pub fn get_proof(&self, index: usize) -> Result<([Fp; MERKLE_DEPTH], Fp)> {
        if index >= self.next_index {
            anyhow::bail!("Invalid leaf index");
        }

        let mut path = [Fp::zero(); MERKLE_DEPTH];
        let mut current_index = index;
        let root;

        {
            let db = self.db.lock().unwrap();
            for level in 0..MERKLE_DEPTH {
                let sibling_index = current_index ^ 1;
                let key = format!("node:{}:{}", level, sibling_index);

                path[level] = db
                    .get(key.as_bytes())?
                    .and_then(|bytes| {
                        if bytes.len() == 32 {
                            let mut arr = [0u8; 32];
                            arr.copy_from_slice(&bytes);
                            Fp::from_repr(arr).into()
                        } else {
                            None
                        }
                    })
                    .unwrap_or(Fp::zero());

                current_index >>= 1;
            }

            root = db
                .get(b"meta:root")?
                .and_then(|bytes| {
                    if bytes.len() == 32 {
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(&bytes);
                        Fp::from_repr(arr).into()
                    } else {
                        None
                    }
                })
                .unwrap_or(Fp::zero());
        }

        Ok((path, root))
    }

    pub fn get_root(&self) -> Fp {
        let db = self.db.lock().unwrap();
        db.get(b"meta:root")
            .ok()
            .flatten()
            .and_then(|bytes| {
                if bytes.len() == 32 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&bytes);
                    Fp::from_repr(arr).into()
                } else {
                    None
                }
            })
            .unwrap_or(Fp::zero())
    }

    pub fn get_anonymity_set_size(&self) -> usize {
        self.next_index
    }

    /// Get shared DB reference for other components (e.g., KeyRotationManager)
    pub fn get_db(&self) -> Arc<Mutex<DB>> {
        self.db.clone()
    }

    pub fn get_leaf_index(&self, leaf: &Fp) -> Option<usize> {
        let db = self.db.lock().unwrap();
        let leaf_hash = hex::encode(leaf.to_repr());
        let key = format!("index:{}", leaf_hash);

        db.get(key.as_bytes()).ok().flatten().and_then(|bytes| {
            if bytes.len() == 8 {
                let mut arr = [0u8; 8];
                arr.copy_from_slice(&bytes);
                Some(usize::from_le_bytes(arr))
            } else {
                None
            }
        })
    }

    fn update_path_batch(
        &self,
        db: &DB,
        batch: &mut WriteBatch,
        leaf_index: usize,
        leaf: Fp,
    ) -> Result<()> {
        let mut current_index = leaf_index;
        let mut current_value = leaf;

        // Store leaf index mapping
        let leaf_hash = hex::encode(leaf.to_repr());
        let index_key = format!("index:{}", leaf_hash);
        batch.put(index_key.as_bytes(), &leaf_index.to_le_bytes());

        for level in 0..MERKLE_DEPTH {
            let node_key = format!("node:{}:{}", level, current_index);
            let node_repr = current_value.to_repr();
            let node_bytes: &[u8] = node_repr.as_ref();
            batch.put(node_key.as_bytes(), node_bytes);

            let sibling_index = current_index ^ 1;
            let sibling_key = format!("node:{}:{}", level, sibling_index);

            let sibling_value = db
                .get(sibling_key.as_bytes())?
                .and_then(|bytes| {
                    if bytes.len() == 32 {
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(&bytes);
                        Fp::from_repr(arr).into()
                    } else {
                        None
                    }
                })
                .unwrap_or(Fp::zero());

            let (left, right) = if current_index & 1 == 0 {
                (current_value, sibling_value)
            } else {
                (sibling_value, current_value)
            };

            current_value = poseidon::Hash::<
                _,
                poseidon::P128Pow5T3,
                poseidon::ConstantLength<2>,
                WIDTH,
                RATE,
            >::init()
            .hash([left, right]);

            current_index >>= 1;
        }

        let root_repr = current_value.to_repr();
        let root_bytes: &[u8] = root_repr.as_ref();
        batch.put(b"meta:root", root_bytes);
        Ok(())
    }
}
