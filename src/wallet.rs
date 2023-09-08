use std::{str::FromStr, collections::{BTreeMap, HashMap}};

use bitcoin::{Address, Network, Transaction, absolute, TxIn, OutPoint, ScriptBuf, Witness, psbt::{Psbt, Input, PsbtSighashType, self}, TxOut, bip32::{Fingerprint, DerivationPath}, Amount, sighash::{TapSighashType, SighashCache, self, TapSighash}, taproot::{TapLeafHash, self}, secp256k1, key::TapTweak};
use secp256k1_zkp::{Secp256k1, XOnlyPublicKey, PublicKey, SecretKey};
use sqlx::{Sqlite, Row};

pub async fn get_all_addresses(pool: &sqlx::Pool<Sqlite>, network: Network) -> Vec::<Address>{
    let query = "SELECT p2tr_address FROM signer_data";

    let rows = sqlx::query(query)
        .fetch_all(pool)
        .await
        .unwrap();

    let mut addresses = Vec::<Address>::new();

    for row in rows {

        let p2tr_address = row.get::<String, _>("p2tr_address");
        let address = Address::from_str(&p2tr_address).unwrap().require_network(network).unwrap();
        addresses.push(address);
    }

    addresses
}

pub async fn get_all_addresses_info(pool: &sqlx::Pool<Sqlite>, network: Network) -> Vec::<(Address, String, String, XOnlyPublicKey, SecretKey)>{
    let query = "SELECT p2tr_address, fingerprint, derivation_path, client_pubkey, client_seckey FROM signer_data";

    let rows = sqlx::query(query)
        .fetch_all(pool)
        .await
        .unwrap();

    let mut addresses = Vec::<(Address, String, String, XOnlyPublicKey, SecretKey)>::new();

    for row in rows {

        let p2tr_address = row.get::<String, _>("p2tr_address");
        let fingerprint = row.get::<String, _>("fingerprint");
        let derivation_path = row.get::<String, _>("derivation_path");
        let address = Address::from_str(&p2tr_address).unwrap().require_network(network).unwrap();

        let public_key_bytes = row.get::<Vec<u8>, _>("client_pubkey");
        let xonly_public_key = PublicKey::from_slice(&public_key_bytes).unwrap().x_only_public_key().0;

        let secret_key_bytes = row.get::<Vec<u8>, _>("client_seckey");
        let secret_key = SecretKey::from_slice(&secret_key_bytes).unwrap();

        addresses.push((address, fingerprint, derivation_path, xonly_public_key, secret_key));
    }

    addresses
}

pub struct AddressInfo {
    pub address: Address,
    pub secret_key: SecretKey,
    pub xonly_public_key: XOnlyPublicKey,
    pub fingerprint: String,
    pub derivation_path: String,
    /// Confirmation height of the transaction that created this output.
    pub height: usize,
    /// Txid of the transaction
    pub tx_hash: bitcoin::Txid,
    /// Index of the output in the transaction.
    pub tx_pos: usize,
    /// Value of the output.
    pub value: u64,
}

pub fn generate_p2tr_key_spend_tx(inputs_info: &Vec::<AddressInfo>, outputs: &Vec<TxOut>) -> Result<Transaction, Box<dyn std::error::Error>> {
    let secp = Secp256k1::new();

    let mut tx_inputs = Vec::<bitcoin::TxIn>::new();

    let mut secret_keys = HashMap::new();

    for input in inputs_info {
        secret_keys.insert(input.xonly_public_key, input.secret_key);
    }

    for input in inputs_info {
        let input_utxo = OutPoint { txid: input.tx_hash, vout: input.tx_pos as u32 };
        let input = TxIn {
            previous_output: input_utxo,
            script_sig: ScriptBuf::new(),
            sequence: bitcoin::Sequence(0xFFFFFFFF), // Ignore nSequence.
            witness: Witness::default(),
        };
        tx_inputs.push(input);
    }

    let tx1 = Transaction {
        version: 2,
        lock_time: absolute::LockTime::ZERO,
        input: tx_inputs,
        output: outputs.clone(),
    };
    let mut psbt = Psbt::from_unsigned_tx(tx1).unwrap();

    let mut origins = BTreeMap::new();
    for input in inputs_info {
        origins.insert(
            input.xonly_public_key,
            (
                vec![],
                (
                    Fingerprint::from_str(&input.fingerprint).unwrap(),
                    DerivationPath::from_str(&input.derivation_path).unwrap(),
                ),
            ),
        );
    }

    let mut psbt_inputs = Vec::<Input>::new();

    for input_info in inputs_info {
        let mut input = Input {
            witness_utxo: {
                let script_pubkey = input_info.address.script_pubkey();
                let amount = Amount::from_sat(input_info.value);
    
                Some(TxOut { value: amount.to_sat(), script_pubkey })
            },
            tap_key_origins: origins.clone(),
            ..Default::default()
        };
        let ty = PsbtSighashType::from_str("SIGHASH_ALL").unwrap();
        input.sighash_type = Some(ty);
        input.tap_internal_key = Some(input_info.xonly_public_key);
        psbt_inputs.push(input);
    }

    psbt.inputs = psbt_inputs;

    // SIGNER
    let unsigned_tx = psbt.unsigned_tx.clone();
    psbt.inputs.iter_mut().enumerate().try_for_each::<_, Result<(), Box<dyn std::error::Error>>>(
        |(vout, input)| {

            let hash_ty = input
                .sighash_type
                .and_then(|psbt_sighash_type| psbt_sighash_type.taproot_hash_ty().ok())
                .unwrap_or(TapSighashType::All);

            let hash = SighashCache::new(&unsigned_tx).taproot_key_spend_signature_hash(
                vout,
                &sighash::Prevouts::All(&[TxOut {
                    value: input.witness_utxo.as_ref().unwrap().value,
                    script_pubkey: input.witness_utxo.as_ref().unwrap().script_pubkey.clone(),
                }]),
                hash_ty,
            ).unwrap();

            let (_, (_, derivation_path)) = input
                .tap_key_origins
                .get(&input.tap_internal_key.ok_or("Internal key missing in PSBT")?)
                .ok_or("Missing taproot key origin").unwrap();

            let secret_key = secret_keys.get(&input.tap_internal_key.ok_or("Internal key missing in PSBT")?).unwrap();

            sign_psbt_taproot(
                &secret_key,
                input.tap_internal_key.unwrap(),
                None,
                input,
                hash,
                hash_ty,
                &secp,
            );

            Ok(())
        },
    ).unwrap();

    // FINALIZER
    psbt.inputs.iter_mut().for_each(|input| {
        let mut script_witness: Witness = Witness::new();
        script_witness.push(input.tap_key_sig.unwrap().to_vec());
        input.final_script_witness = Some(script_witness);

        // Clear all the data fields as per the spec.
        input.partial_sigs = BTreeMap::new();
        input.sighash_type = None;
        input.redeem_script = None;
        input.witness_script = None;
        input.bip32_derivation = BTreeMap::new();
    });

    let tx = psbt.extract_tx();
    
    //let mut prev_out_verify = Vec::<bitcoin::TxOut>::new();
    for input in inputs_info {
        let script_pubkey_hex = input.address.script_pubkey().to_hex_string();
        let amount = Amount::from_sat(input.value);

        //prev_out_verify.push(TxOut { value: amount.to_sat(), script_pubkey });
        tx.verify(|_| {
            Some(TxOut { 
                value: amount.to_sat(), 
                script_pubkey: ScriptBuf::from_hex(&script_pubkey_hex).unwrap() 
            })
        })
        .expect("failed to verify transaction");
    }

    Ok(tx)

}

fn sign_psbt_taproot(
    secret_key: &SecretKey,
    pubkey: XOnlyPublicKey,
    leaf_hash: Option<TapLeafHash>,
    psbt_input: &mut psbt::Input,
    hash: TapSighash,
    hash_ty: TapSighashType,
    secp: &Secp256k1<secp256k1::All>,
) {
    let keypair = secp256k1::KeyPair::from_seckey_slice(secp, secret_key.as_ref()).unwrap();
    let keypair = match leaf_hash {
        None => keypair.tap_tweak(secp, psbt_input.tap_merkle_root).to_inner(),
        Some(_) => keypair, // no tweak for script spend
    };

    let sig = secp.sign_schnorr(&hash.into(), &keypair);

    let final_signature = taproot::Signature { sig, hash_ty };

    if let Some(lh) = leaf_hash {
        psbt_input.tap_script_sigs.insert((pubkey, lh), final_signature);
    } else {
        psbt_input.tap_key_sig = Some(final_signature);
    }
}

