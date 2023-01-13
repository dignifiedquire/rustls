#[cfg(feature = "crypto-ring")]
pub(crate) use crypto_ring::*;

#[cfg(feature = "crypto-ring")]
mod crypto_ring {
    pub(crate) mod aead {
        #[cfg(feature = "quic")]
        pub(crate) use ring::aead::{quic, Tag};
        pub(crate) use ring::aead::{
            Aad, Algorithm, LessSafeKey, Nonce, UnboundKey, AES_128_GCM, AES_256_GCM,
            CHACHA20_POLY1305, NONCE_LEN,
        };
    }

    pub(crate) mod agreement {
        pub(crate) use ring::agreement::{
            agree_ephemeral, Algorithm, EphemeralPrivateKey, PublicKey, UnparsedPublicKey,
            ECDH_P256, ECDH_P384, X25519,
        };
    }

    pub(crate) mod constant_time {
        pub(crate) use ring::constant_time::verify_slices_are_equal;
    }

    pub(crate) mod digest {
        #[cfg(test)]
        pub(crate) use ring::digest::SHA256;
        pub(crate) use ring::digest::{digest, Algorithm, Context, Digest, MAX_OUTPUT_LEN};
    }

    pub(crate) mod hkdf {
        pub(crate) use ring::hkdf::{Algorithm, KeyType, Okm, Prk, Salt, HKDF_SHA256, HKDF_SHA384};
    }

    pub(crate) mod hmac {
        #[cfg(test)]
        pub(crate) use ring::hmac::HMAC_SHA512;
        pub(crate) use ring::hmac::{sign, Algorithm, Context, Key, Tag, HMAC_SHA256, HMAC_SHA384};
    }

    pub(crate) mod io {
        pub(crate) use ring::io::der;
    }

    pub(crate) mod rand {
        pub(crate) use ring::rand::{SecureRandom, SystemRandom};
    }

    pub(crate) mod signature {
        pub(crate) use ring::signature::*;
    }
}
