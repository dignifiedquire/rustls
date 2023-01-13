#[cfg(feature = "crypto-ring")]
pub use crypto_ring::*;

#[cfg(feature = "crypto-ring")]
mod crypto_ring {
    /// Document me.
    pub mod aead {
        #[cfg(feature = "quic")]
        /// Document me.
        pub mod quic {
            pub use ring::aead::quic::{HeaderProtectionKey, AES_128, AES_256, CHACHA20};
        }

        #[cfg(feature = "quic")]
        pub use ring::aead::Tag;
        pub use ring::aead::{
            Aad, Algorithm, LessSafeKey, Nonce, UnboundKey, AES_128_GCM, AES_256_GCM,
            CHACHA20_POLY1305, NONCE_LEN,
        };
    }

    /// Document me.
    pub mod agreement {
        pub use ring::agreement::{
            agree_ephemeral, Algorithm, EphemeralPrivateKey, PublicKey, UnparsedPublicKey,
            ECDH_P256, ECDH_P384, X25519,
        };
    }

    /// Document me.
    pub mod constant_time {
        /// Document me.
        pub type CmpError = ring::error::Unspecified;

        /// Document me.
        #[inline(always)]
        pub fn verify_slices_are_equal(a: &[u8], b: &[u8]) -> Result<(), CmpError> {
            ring::constant_time::verify_slices_are_equal(a, b)
        }
    }

    /// Document me.
    pub mod digest {
        pub use ring::digest::{digest, Algorithm, Context, Digest, MAX_OUTPUT_LEN};

        #[cfg(test)]
        pub use ring::digest::SHA256;
    }

    /// Document me.
    pub mod hkdf {
        pub use ring::hkdf::{Algorithm, KeyType, Okm, Prk, Salt, HKDF_SHA256, HKDF_SHA384};
    }

    /// Document me.
    pub mod hmac {
        pub use ring::hmac::{sign, Algorithm, Context, Key, Tag, HMAC_SHA256, HMAC_SHA384};

        #[cfg(test)]
        pub use ring::hmac::HMAC_SHA512;
    }

    /// Document me.
    pub mod io {
        /// Document me.
        pub mod der {
            pub use ring::io::der::Tag;
        }
    }

    /// Document me.
    pub mod rand {
        /// Document me.
        #[derive(Debug)]
        pub struct GetRandomFailed;

        pub use ring::rand::SystemRandom;

        /// Fill the whole slice with random material.
        pub fn fill_random(bytes: &mut [u8]) -> Result<(), GetRandomFailed> {
            use ring::rand::SecureRandom;

            ring::rand::SystemRandom::new()
                .fill(bytes)
                .map_err(|_| GetRandomFailed)
        }
    }

    /// Document me.
    pub mod signature {
        pub use ring::signature::{
            EcdsaKeyPair, EcdsaSigningAlgorithm, Ed25519KeyPair, RsaEncoding, RsaKeyPair,
            ECDSA_P256_SHA256_ASN1_SIGNING, ECDSA_P384_SHA384_ASN1_SIGNING, RSA_PKCS1_SHA256,
            RSA_PKCS1_SHA384, RSA_PKCS1_SHA512, RSA_PSS_SHA256, RSA_PSS_SHA384, RSA_PSS_SHA512,
        };
    }

    /// Document me.
    pub mod sct {
        pub use sct::{Error, Log};

        /// Verifies that the SCT `sct` (a `SignedCertificateTimestamp` encoding)
        /// is a correctly signed timestamp for `cert` (a DER-encoded X.509 end-entity
        /// certificate) valid `at_time`.  `logs` describe the CT logs trusted by
        /// the caller to sign such an SCT.
        ///
        /// On success, this function returns the log used as an index into `logs`.
        /// Otherwise, it returns an `Error`.
        pub fn verify_sct(
            cert: &[u8],
            sct: &[u8],
            at_time: u64,
            logs: &[&Log<'_>],
        ) -> Result<usize, Error> {
            sct::verify_sct(cert, sct, at_time, logs)
        }
    }

    /// Document me.
    pub mod webpki {
        pub use webpki::{
            DnsName, DnsNameRef, EndEntityCert, Error, InvalidDnsNameError, IpAddr, IpAddrRef,
            SignatureAlgorithm, SubjectNameRef, Time, TlsClientTrustAnchors, TlsServerTrustAnchors,
            TrustAnchor, ECDSA_P256_SHA256, ECDSA_P256_SHA384, ECDSA_P384_SHA256,
            ECDSA_P384_SHA384, ED25519, RSA_PKCS1_2048_8192_SHA256, RSA_PKCS1_2048_8192_SHA384,
            RSA_PKCS1_2048_8192_SHA512, RSA_PKCS1_3072_8192_SHA384,
            RSA_PSS_2048_8192_SHA256_LEGACY_KEY, RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
            RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
        };
    }
}
