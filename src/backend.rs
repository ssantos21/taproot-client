use bitcoin::Txid;
use electrum_client::{GetBalanceRes, ElectrumApi, GetHistoryRes, ListUnspentRes};

/// return balance of address
pub fn get_address_balance(electrum_client: &electrum_client::Client, address: &bitcoin::Address) -> GetBalanceRes {
    electrum_client.script_get_balance(&address.script_pubkey()).unwrap()
}

pub fn get_address_history(electrum_client: &electrum_client::Client, address: &bitcoin::Address) -> Vec<GetHistoryRes> {
    electrum_client.script_get_history(&address.script_pubkey()).unwrap()
}

pub fn get_script_list_unspent(electrum_client: &electrum_client::Client, address: &bitcoin::Address) -> Vec<ListUnspentRes> {    
    electrum_client.script_list_unspent(&address.script_pubkey()).unwrap()
}

pub fn transaction_broadcast_raw(electrum_client: &electrum_client::Client, raw_tx: &[u8]) -> Txid {    
    electrum_client.transaction_broadcast_raw(raw_tx).unwrap()
}
