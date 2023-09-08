CREATE TABLE IF NOT EXISTS signer_seed (
    seed BLOB
);

CREATE TABLE IF NOT EXISTS signer_data (
    bip32_index INT,
    client_seckey BLOB,
    client_pubkey BLOB,
    p2tr_address TEXT,
    is_change INT,
    fingerprint TEXT,
    derivation_path TEXT
);