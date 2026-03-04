//! Merkle tree for batch proof aggregation

use crate::core::errors::{Result, ZKGuardError};
use crate::utils::constants::DOMAIN_MERKLE;
use crate::utils::hash::combine_hashes;

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

#[cfg(feature = "alloc")]
#[derive(Debug)]
pub struct MerkleTree {
    layers: Vec<Vec<[u8; 32]>>,
}

#[cfg(feature = "alloc")]
#[derive(Debug)]
pub struct MerklePath {
    pub path: Vec<[u8; 32]>,
    pub index: usize,
}

#[cfg(feature = "alloc")]
impl MerkleTree {
    pub fn new(leaves: Vec<[u8; 32]>) -> Result<Self> {
        if leaves.is_empty() {
            return Err(ZKGuardError::MerkleError {
                reason: "empty leaves".into(),
            });
        }
        let mut layers: Vec<Vec<[u8; 32]>> = Vec::new();
        layers.push(leaves);

        while layers.last().unwrap().len() > 1 {
            let prev = layers.last().unwrap();
            let mut next = Vec::with_capacity(prev.len().div_ceil(2));
            for i in (0..prev.len()).step_by(2) {
                let left = &prev[i];
                let right = if i + 1 < prev.len() {
                    &prev[i + 1]
                } else {
                    &prev[i]
                };
                next.push(combine_hashes(left, right, DOMAIN_MERKLE));
            }
            layers.push(next);
        }

        Ok(Self { layers })
    }

    pub fn root(&self) -> Result<[u8; 32]> {
        self.layers
            .last()
            .and_then(|l| l.first())
            .copied()
            .ok_or_else(|| ZKGuardError::MerkleError {
                reason: "empty tree".into(),
            })
    }

    pub fn path(&self, mut index: usize) -> Result<MerklePath> {
        if index >= self.layers[0].len() {
            return Err(ZKGuardError::MerkleError {
                reason: alloc::format!("index {} out of range", index),
            });
        }
        let orig = index;
        let mut path = Vec::new();
        for layer in &self.layers[..self.layers.len() - 1] {
            let sibling = if index.is_multiple_of(2) {
                if index + 1 < layer.len() {
                    layer[index + 1]
                } else {
                    layer[index]
                }
            } else {
                layer[index - 1]
            };
            path.push(sibling);
            index /= 2;
        }
        Ok(MerklePath { path, index: orig })
    }

    pub fn verify_path(root: &[u8; 32], leaf: &[u8; 32], path: &MerklePath) -> bool {
        let mut current = *leaf;
        let mut idx = path.index;
        for sibling in &path.path {
            current = if idx.is_multiple_of(2) {
                combine_hashes(&current, sibling, DOMAIN_MERKLE)
            } else {
                combine_hashes(sibling, &current, DOMAIN_MERKLE)
            };
            idx /= 2;
        }
        crate::utils::hash::constant_time_eq_fixed(root, &current)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaf(v: u8) -> [u8; 32] {
        let mut l = [0u8; 32];
        l[0] = v;
        l
    }

    #[test]
    fn test_single_leaf() {
        let t = MerkleTree::new(alloc::vec![leaf(1)]).unwrap();
        assert_eq!(t.root().unwrap(), leaf(1));
    }

    #[test]
    fn test_path_verify() {
        let leaves: Vec<[u8; 32]> = (0..4).map(leaf).collect();
        let tree = MerkleTree::new(leaves.clone()).unwrap();
        let root = tree.root().unwrap();
        for (i, leaf) in leaves.iter().enumerate() {
            let path = tree.path(i).unwrap();
            assert!(MerkleTree::verify_path(&root, leaf, &path));
        }
    }

    #[test]
    fn test_empty_tree_error() {
        assert!(MerkleTree::new(alloc::vec![]).is_err());
    }
}
