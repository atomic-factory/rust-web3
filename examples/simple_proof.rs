extern crate web3;
extern crate tokio_core;
extern crate env_logger;

use std::str::FromStr;
use web3::{
    api::Namespace,
    futures::Future,
    types::H256
};

fn main() {
    env_logger::init();

    let mut event_loop = tokio_core::reactor::Core::new().unwrap();
    let bl = web3::api::Darwinia::new(
        web3::transports::Http::with_event_loop(
            "http://localhost:8545",
            &event_loop.handle(),
            64,
        ).unwrap(),
    );
    let hash = H256::from_str("51451f18d596927bdc1817e15223ec4d0d9526d04db4963dd688c9e1a312956e").unwrap();
    let proof = event_loop.run(bl.receipt_proof(hash)).unwrap();
    println!("Proof: {:?}", proof);
}