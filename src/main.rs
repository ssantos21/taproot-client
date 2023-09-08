mod backend;
mod addresses;
mod wallet;

use std::str::FromStr;

use bitcoin::{Address, TxOut};
use clap::{Parser, Subcommand};
use electrum_client::ListUnspentRes;
use secp256k1_zkp::Secp256k1;
use serde::{Serialize, Deserialize};
use serde_json::json;
use sqlx::{SqlitePool, Sqlite, migrate::MigrateDatabase};

use crate::wallet::generate_p2tr_key_spend_tx;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Create Aggregated Public Key
    GenerateNewKey {},
    /// List Aggregated Public Keys
    ListAddresses {},
    /// Get a wallet balance
    GetBalance { },
    /// List transactions
    ListTransactions { },
    /// Send coin to an address
    Send { address: String, amount: u64, fees: u64 },
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let network = bitcoin::Network::Signet;

    let client = electrum_client::Client::new("tcp://127.0.0.1:50001").unwrap();

    let cli = Cli::parse();

    if !Sqlite::database_exists("wallet.db").await.unwrap_or(false) {
        match Sqlite::create_database("wallet.db").await {
            Ok(_) => println!("Create db success"),
            Err(error) => panic!("error: {}", error),
        }
    }

    let pool = SqlitePool::connect("wallet.db").await.unwrap();

    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .unwrap();

    match cli.command {
    Commands::GenerateNewKey {  } => {
        let (public_key, address, bip32index) = addresses::generate_new_key(&pool, network, false).await;

        let res = json!({
            "index": bip32index,
            "public_key": public_key.to_string(),
            "address": address
        });
        println!("{}", serde_json::to_string_pretty(&res).unwrap());
        
    },
    Commands::ListAddresses {  } => {
        let addresses = wallet::get_all_addresses(&pool, network).await;
        println!("{}", serde_json::to_string_pretty(&json!(addresses)).unwrap());
    },
    Commands::GetBalance {  } => {

        #[derive(Serialize, Deserialize, Debug)]
            struct Balance {
                address: String,
                balance: u64,
                unconfirmed_balance: i64,
            }

            let addresses = wallet::get_all_addresses(&pool, network).await;
            let result: Vec<Balance> = addresses.iter().map(|address| {
                let balance_res = backend::get_address_balance(&client, &address);
                Balance {
                    address: address.to_string(),
                    balance: balance_res.confirmed,
                    unconfirmed_balance: balance_res.unconfirmed,
                }
            }).collect();

            println!("{}", serde_json::to_string_pretty(&json!(result)).unwrap());

    },
    Commands::ListTransactions {  } => {
        #[derive(Serialize, Deserialize, Debug)]
            struct History {
                address: String,
                tx_hash: String,
                height: i32,
            }

            let addresses = wallet::get_all_addresses(&pool, network).await;
            let mut result: Vec<History> = Vec::new();

            for address in addresses {
                let history_vector = backend::get_address_history(&client, &address);
                for history in history_vector {
                    result.push(History {
                        address: address.to_string(),
                        tx_hash: history.tx_hash.to_string(),
                        height: history.height,
                    });
                }
            }
            
            println!("{}", serde_json::to_string_pretty(&json!(result)).unwrap());
    },
    Commands::Send { address, amount, fees } => {
        let to_address = Address::from_str(&address).unwrap().require_network(network).unwrap();

        let (_, change_address, _) = addresses::generate_new_key(&pool, network, true).await;

        let amount_to_send_in_sats = bitcoin::Amount::from_sat(amount);

        let addresses = wallet::get_all_addresses_info(&pool, network).await;

        let mut list_unspent = Vec::<wallet::AddressInfo>::new(); 

        for address in addresses {
            let address_utxos = backend::get_script_list_unspent(&client, &address.0);

            for utxo in address_utxos {
                list_unspent.push(wallet::AddressInfo {
                    address: address.0.clone(),
                    secret_key: address.4.clone(),
                    xonly_public_key: address.3.clone(),
                    fingerprint: address.1.clone(),
                    derivation_path: address.2.clone(),
                    height: utxo.height,
                    tx_hash: utxo.tx_hash,
                    tx_pos: utxo.tx_pos,
                    value: utxo.value,
                });
            }
        }

        list_unspent.sort_by(|a, b| a.value.cmp(&b.value));

        let mut previous_outputs = Vec::<wallet::AddressInfo>::new(); 

        for utxo in list_unspent {
            
            let input_amount: u64 = previous_outputs.iter().map(|s| s.value).sum();

            if (input_amount) > (amount + fees) {
                break;
            } else {
                previous_outputs.push(utxo);
            }
        }

        let input_amount: u64 = previous_outputs.iter().map(|s| s.value).sum();
        println!("input_amount: {}", input_amount);
        println!("amount + fee: {}", (amount + fees));

        if (input_amount) < (amount + fees) {
            let res = json!({
                "error": "Not enough funds",
            });
            println!("{}", serde_json::to_string_pretty(&res).unwrap());
            return;
        }

        let input_amount_in_sats = bitcoin::Amount::from_sat(input_amount);
        let fees_amount_in_sats = bitcoin::Amount::from_sat(fees);

        let change_amount = input_amount_in_sats
            .checked_sub(amount_to_send_in_sats)
            .and_then(|x| x.checked_sub(fees_amount_in_sats))
            .ok_or("Fees more than input amount!").unwrap();

        let outputs = vec![
            TxOut { value: amount_to_send_in_sats.to_sat(), script_pubkey: to_address.script_pubkey() },
            TxOut { value: change_amount.to_sat(), script_pubkey: change_address.script_pubkey() },
        ];


        let tx = generate_p2tr_key_spend_tx(&previous_outputs, &outputs).unwrap();
        let tx_hex_string = bitcoin::consensus::encode::serialize_hex(&tx);

        let tx_bytes = bitcoin::consensus::encode::serialize(&tx);

        println!("tx_hex: {}", tx_hex_string);

        let txid = backend::transaction_broadcast_raw(&client, &tx_bytes);

        println!("txid: {}", txid);
    },
}
}
    
