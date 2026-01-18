# PQ_KEMS = {
#     "X25519Kyber512Draft00",
#     "X25519Kyber768Draft00",
#     "P256_Kyber512",
#     "P256_Kyber768",
#     "kyber512",
#     "kyber768",
# }


# PQ_SIGNATURES = {
#     "dilithium2",
#     "dilithium3",
#     "dilithium5",
#     "falcon512",
#     "falcon1024",
#     "sphincs+",
# }

PQS_SIGNATURES = {
    "2.16.840.1.101.3.4.3.17",  # ML-DSA-44 (CRYSTALS-Dilithium2)
    "2.16.840.1.101.3.4.3.18",  # ML-DSA-65 (CRYSTALS-Dilithium3)
    "2.16.840.1.101.3.4.3.19",  # ML-DSA-87 (CRYSTALS-Dilithium5)

    "2.16.840.1.101.3.4.3.35",  # SLH-DSA-SHA2-128s-with-SHA256 (SPHINCS+)
    "2.16.840.1.101.3.4.3.36",  # SLH-DSA-SHA2-128f-with-SHA256 (SPHINCS+)
    "2.16.840.1.101.3.4.3.37",  # SLH-DSA-SHA2-192s-with-SHA384 (SPHINCS+)
    "2.16.840.1.101.3.4.3.38",  # SLH-DSA-SHA2-192f-with-SHA384 (SPHINCS+)
    "2.16.840.1.101.3.4.3.39",  # SLH-DSA-SHA2-256s-with-SHA512 (SPHINCS+)
    "2.16.840.1.101.3.4.3.40",  # SLH-DSA-SHA2-256f-with-SHA512 (SPHINCS+)

    "2.16.840.1.101.3.4.3.41",  # SLH-DSA-SHAKE-128s-with-SHA256 (SPHINCS+)
    "2.16.840.1.101.3.4.3.42",  # SLH-DSA-SHAKE-128f-with-SHA256 (SPHINCS+)
    "2.16.840.1.101.3.4.3.43",  # SLH-DSA-SHAKE-192s-with-SHA384 (SPHINCS+)
    "2.16.840.1.101.3.4.3.44",  # SLH-DSA-SHAKE-192f-with-SHA384 (SPHINCS+)
    "2.16.840.1.101.3.4.3.45",  # SLH-DSA-SHAKE-256s-with-SHA512 (SPHINCS+)
    "2.16.840.1.101.3.4.3.46",  # SLH-DSA-SHAKE-256f-with-SHA512 (SPHINCS+)
}

PQS_KEMS = {
    "2.16.840.1.101.3.4.4.1",  # ML-KEM-512  (CRYSTALS-Kyber512, NIST security category 1)
    "2.16.840.1.101.3.4.4.2",  # ML-KEM-768  (CRYSTALS-Kyber768, NIST security category 3)
    "2.16.840.1.101.3.4.4.3",  # ML-KEM-1024 (CRYSTALS-Kyber1024, NIST security category 5)
}

#hashes of algorithms for easier checking
PQS_SIGNATURES_OID_TO_NAME = {
    "2.16.840.1.101.3.4.3.17": "ML-DSA-44 (CRYSTALS-Dilithium2)",
    "2.16.840.1.101.3.4.3.18": "ML-DSA-65 (CRYSTALS-Dilithium3)",
    "2.16.840.1.101.3.4.3.19": "ML-DSA-87 (CRYSTALS-Dilithium5)",

    "2.16.840.1.101.3.4.3.35": "SLH-DSA-SHA2-128s-with-SHA256 (SPHINCS+)",
    "2.16.840.1.101.3.4.3.36": "SLH-DSA-SHA2-128f-with-SHA256 (SPHINCS+)",
    "2.16.840.1.101.3.4.3.37": "SLH-DSA-SHA2-192s-with-SHA384 (SPHINCS+)",
    "2.16.840.1.101.3.4.3.38": "SLH-DSA-SHA2-192f-with-SHA384 (SPHINCS+)",
    "2.16.840.1.101.3.4.3.39": "SLH-DSA-SHA2-256s-with-SHA512 (SPHINCS+)",
    "2.16.840.1.101.3.4.3.40": "SLH-DSA-SHA2-256f-with-SHA512 (SPHINCS+)",

    "2.16.840.1.101.3.4.3.41": "SLH-DSA-SHAKE-128s-with-SHA256 (SPHINCS+)",
    "2.16.840.1.101.3.4.3.42": "SLH-DSA-SHAKE-128f-with-SHA256 (SPHINCS+)",
    "2.16.840.1.101.3.4.3.43": "SLH-DSA-SHAKE-192s-with-SHA384 (SPHINCS+)",
    "2.16.840.1.101.3.4.3.44": "SLH-DSA-SHAKE-192f-with-SHA384 (SPHINCS+)",
    "2.16.840.1.101.3.4.3.45": "SLH-DSA-SHAKE-256s-with-SHA512 (SPHINCS+)",
    "2.16.840.1.101.3.4.3.46": "SLH-DSA-SHAKE-256f-with-SHA512 (SPHINCS+)",
}

# Quantum-safe KEM OIDs → name
PQS_KEMS_OID_TO_NAME = {
    "2.16.840.1.101.3.4.4.1": "ML-KEM-512 (CRYSTALS-Kyber512)",
    "2.16.840.1.101.3.4.4.2": "ML-KEM-768 (CRYSTALS-Kyber768)",
    "2.16.840.1.101.3.4.4.3": "ML-KEM-1024 (CRYSTALS-Kyber1024)",
}