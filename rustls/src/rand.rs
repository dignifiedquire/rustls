//! The single place where we generate random material for our own use.

pub(crate) use crate::crypto::rand::{fill_random, GetRandomFailed};

/// Make a Vec<u8> of the given size
/// containing random material.
pub(crate) fn random_vec(len: usize) -> Result<Vec<u8>, GetRandomFailed> {
    let mut v = vec![0; len];
    fill_random(&mut v)?;
    Ok(v)
}

/// Return a uniformly random u32.
pub(crate) fn random_u32() -> Result<u32, GetRandomFailed> {
    let mut buf = [0u8; 4];
    fill_random(&mut buf)?;
    Ok(u32::from_be_bytes(buf))
}
