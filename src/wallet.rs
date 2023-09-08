use std::str::FromStr;

use bitcoin::{Address, Network};
use secp256k1_zkp::Secp256k1;
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

fn generate_p2tr_key_spend_tx() {
    let secp = Secp256k1::new();
}

