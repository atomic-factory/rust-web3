//! `darwinia` namespace

use crate::api::{Namespace, Eth};
use crate::helpers::{self, CallFuture, BatchCallFuture};
use crate::types::{Address, Block, BlockId, BlockNumber, Bytes, CallRequest, H256, H520, H64, U128, Index, SyncState, Transaction, TransactionId, TransactionReceipt, TransactionRequest, U256, Work, Filter, Log, RawHeader, RawReceipt};
use crate::error::Error;
use crate::{RequestId, BatchTransport};
use trie::{Trie, build_order_trie, Proof};
use futures::{Future, IntoFuture, Poll, Stream};
use jsonrpc_core as rpc;

/// `Darwinia` namespace
#[derive(Debug, Clone)]
pub struct Darwinia<T> {
    transport: T,
}

impl<T: BatchTransport> Namespace<T> for Darwinia<T> {
    fn new(transport: T) -> Self
        where
            Self: Sized,
    {
        Darwinia { transport }
    }

    fn transport(&self) -> &T {
        &self.transport
    }
}

impl<T: BatchTransport> Darwinia<T> {

    /// Get raw block header
    pub fn raw_header(&self, block_id:BlockId) -> impl Future<Item = Option<RawHeader>, Error = Error> {
        let eth = Eth::new(self.transport().clone());
        eth.block(block_id).and_then(|block| {
            match block {
                Some(b) => Ok(Some(b.into()).into()),
                None => Ok(None.into()),
            }
        })
    }

    /// Get raw transaction receipt
    pub fn raw_transaction_receipt(&self, hash: H256) -> impl Future<Item = Option<RawReceipt>, Error = Error> {
        let eth = Eth::new(self.transport().clone());
        eth.transaction_receipt(hash).and_then(|recepit| {
            match recepit {
                Some(r) => Ok(Some(RawReceipt::from(r)).into()),
                None => Ok(None.into()),
            }
        })
    }

    /// Get receipts by batch sending
    pub fn receipts(&self, hashs:Vec<H256>) -> BatchCallFuture<Option<TransactionReceipt>, T::Batch> {
        let requests = hashs.into_iter().map(|hash| {
            let req = helpers::serialize(&hash);
            self.transport.prepare("eth_getTransactionReceipt", vec![req])
        }).collect::<Vec<(RequestId, rpc::Call)>>();

        BatchCallFuture::new(self.transport.send_batch(requests))
    }

    /// Get blocks by batch sending
    pub fn blocks(&self, block_ids: Vec<BlockId>) -> BatchCallFuture<Option<Block<H256>>, T::Batch> {
        let requests = block_ids.into_iter().map(|block_id| {
            let req = helpers::serialize(&block_id);
            let include_txs = helpers::serialize(&false);
            let result = match block_id {
                BlockId::Hash(hash) => {
                    let hash = helpers::serialize(&hash);
                    self.transport.prepare("eth_getBlockByHash", vec![hash, include_txs])
                }
                BlockId::Number(num) => {
                    let num = helpers::serialize(&num);
                    self.transport.prepare("eth_getBlockByNumber", vec![num, include_txs])
                }
            };
            result
        }).collect::<Vec<(RequestId, rpc::Call)>>();

        BatchCallFuture::new(self.transport.send_batch(requests))
    }

    /// Get receipt proof
    pub fn receipt_proof(&self, hash: H256) -> ReceiptProof<T> {
        let hash = TransactionId::Hash(hash);
        let eth = Eth::new(self.transport().clone());
        ReceiptProof::new(ReceiptProofState::Transaction(eth.transaction(hash)), eth)
    }
}

pub enum ReceiptProofState<T: BatchTransport> {
    Transaction(CallFuture<Option<Transaction>, T::Out>),
    Block(Transaction, CallFuture<Option<Block<H256>>, T::Out>),
    Receipts(Transaction, Block<H256>, BatchCallFuture<Option<TransactionReceipt>, T::Batch>),
}

pub struct ReceiptProof<T: BatchTransport> {
    eth: Eth<T>,
    state: ReceiptProofState<T>,
}

impl<T: BatchTransport> ReceiptProof<T> {
    pub fn new(state: ReceiptProofState<T>, eth: Eth<T>) -> Self {
        ReceiptProof {
            eth,
            state,
        }
    }
}

impl<T: BatchTransport> Future for ReceiptProof<T> {
    type Item = Option<(u64, Vec<u8>, H256)>;
    type Error = Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        loop {
            let next = match self.state {
                ReceiptProofState::Transaction(ref mut future) => {
                    let trans = try_ready!(future.poll());
                    if let Some(t) = trans {
                        let block_id = BlockId::Hash(t.block_hash.unwrap());
                        ReceiptProofState::Block(t, self.eth.block(block_id))
                    } else {
                        return Ok(None.into())
                    }
                },
                ReceiptProofState::Block(ref transaction, ref mut future) => {
                    let bl = Darwinia::new(self.eth.transport().clone());
                    let block = try_ready!(future.poll());
                    if let Some(b) = block {
                        let hashs = b.transactions.clone();
                        ReceiptProofState::Receipts(transaction.clone(), b, bl.receipts(hashs))
                    } else {
                        return Ok(None.into())
                    }
                },
                ReceiptProofState::Receipts(ref transaction, ref block, ref mut future) => {
                    let receipts = try_ready!(future.poll());
                    // build proof
                    let raw_receipts:Vec<RawReceipt> = receipts.into_iter().filter(|x| x.is_some()).map(|x| {x.unwrap().into()}).collect();
                    if raw_receipts.len() != block.transactions.len() {
                        return Err(Error::InvalidResponse("Expected got batch success".into()).into());
                    }
                    let rlp_receipts:Vec<Vec<u8>> = raw_receipts.into_iter().map(|r| rlp::encode(&r)).collect();
                    let transaction_index: U128 = transaction.transaction_index.ok_or(Error::InvalidResponse("Expected transaction index".into()))?;
                    let index = transaction_index.low_u64() as usize;
                    let mut trie = build_order_trie(rlp_receipts)?;
                    // check status root.
                    let root = trie.root()?;
                    if root != block.receipts_root.as_ref() {
                        return Err(Error::InvalidResponse("Expected valid receipts root".into()).into())
                    }
                    let proof = trie.get_proof(&rlp::encode(&index))?;
                    let rlp_proof = proof.to_rlp();
                    let header_hash = block.hash.unwrap_or_else(|| RawHeader::from(block.clone()).hash());
                    return Ok(Some((index as u64, rlp_proof, header_hash)).into())
                }
            };

            self.state = next;
        }
    }
}
