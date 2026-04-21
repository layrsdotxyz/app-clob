use crate::{
    error::{ClobError, ClobResult},
    models::Trade,
    proof_generation::{CircuitInput, OrderMatchProofData},
    redis_store::RedisStore,
};
use rust_decimal::prelude::ToPrimitive;
use std::collections::HashMap;
use std::process::Command;
use std::sync::Arc;
use tracing::{error, info, warn};

pub struct OrderMatchProver {
    redis: Arc<RedisStore>,
    circuit_path: String,
}

impl OrderMatchProver {
    pub fn new(redis: Arc<RedisStore>) -> Self {
        let circuit_path = std::env::var("CIRCUIT_PATH")
            .unwrap_or_else(|_| "/home/zoopx/zoopx/layrs/circuits".to_string());

        Self {
            redis,
            circuit_path,
        }
    }

    /// Generate ORDER_MATCH proof for an epoch
    pub async fn generate_order_match_proof(
        &self,
        epoch_id: u64,
        market_id: &str,
        trades: &[Trade],
    ) -> ClobResult<OrderMatchProofData> {
        info!(
            epoch_id,
            market_id,
            num_trades = trades.len(),
            "Generating ORDER_MATCH proof"
        );

        // 1. Collect orders involved in trades
        let orders = self.collect_orders_from_trades(trades).await?;

        // 2. Generate circuit inputs
        let circuit_input = self.prepare_circuit_input(epoch_id, market_id, &orders, trades)?;

        // 3. Write input file
        let input_file = format!("{}/order_match_input_{}.json", self.circuit_path, epoch_id);
        std::fs::write(&input_file, serde_json::to_string_pretty(&circuit_input)?)?;

        info!(epoch_id, "Circuit input written to {}", input_file);

        // 4. Generate witness
        let witness_file = self.generate_witness(epoch_id)?;

        // 5. Generate proof
        let (proof, public_signals) = self.generate_proof(epoch_id, &witness_file)?;

        info!(epoch_id, "Proof generated successfully");

        // 6. Compute proof metadata
        let order_batch_hash = self.compute_order_batch_hash(&orders);
        let matching_root = self.compute_matching_root(trades);
        let public_inputs_hash = self.compute_public_inputs_hash(&public_signals);

        // 7. Calculate metrics
        let total_volume: u64 = trades.iter().map(|t| t.size.to_string().parse::<u64>().unwrap_or(0)).sum();
        let unique_users: std::collections::HashSet<String> = trades
            .iter()
            .flat_map(|t| vec![t.maker_user_id.clone(), t.taker_user_id.clone()])
            .collect();

        let proof_data = OrderMatchProofData {
            proof_id: format!("proof_{}_{}", epoch_id, market_id),
            epoch_id,
            market_id: market_id.to_string(),
            order_batch_hash,
            matching_root,
            public_inputs_hash,
            total_volume,
            unique_users: unique_users.len(),
        };

        // 9. Store proof metadata
        self.store_proof_metadata(&proof_data).await?;

        info!(
            epoch_id,
            proof_id = %proof_data.proof_id,
            "ORDER_MATCH proof generation complete"
        );

        Ok(proof_data)
    }

    async fn collect_orders_from_trades(&self, trades: &[Trade]) -> ClobResult<Vec<crate::models::Order>> {
        let mut orders = Vec::new();
        let mut seen_ids = std::collections::HashSet::new();

        for trade in trades {
            if !seen_ids.contains(&trade.maker_order_id) {
                if let Ok(Some(order)) = self.redis.get_order(trade.maker_order_id).await {
                    orders.push(order);
                    seen_ids.insert(trade.maker_order_id);
                }
            }
            if !seen_ids.contains(&trade.taker_order_id) {
                if let Ok(Some(order)) = self.redis.get_order(trade.taker_order_id).await {
                    orders.push(order);
                    seen_ids.insert(trade.taker_order_id);
                }
            }
        }

        Ok(orders)
    }

    fn prepare_circuit_input(
        &self,
        epoch_id: u64,
        _market_id: &str,
        orders: &[crate::models::Order],
        trades: &[Trade],
    ) -> ClobResult<CircuitInput> {
        // Convert orders to circuit format: [id, price, size, timestamp, side]
        let mut order_array = Vec::new();
        let mut order_index_map = HashMap::new();

        for (idx, order) in orders.iter().enumerate() {
            order_index_map.insert(order.id, idx);
            
            let order_id_num = self.order_id_to_field_element(&order.id);
            let price_scaled = (order.price.to_f64().unwrap() * 10000.0) as u64; // Scale to basis points
            let size_scaled = (order.size.to_f64().unwrap() * 1e18) as u64; // Scale to wei
            let timestamp = order.created_at.timestamp() as u64;
            let side = match order.side {
                crate::models::OrderSide::Buy => 0,
                crate::models::OrderSide::Sell => 1,
            };

            order_array.push(vec![
                order_id_num.to_string(),
                price_scaled.to_string(),
                size_scaled.to_string(),
                timestamp.to_string(),
                side.to_string(),
            ]);
        }

        // Pad to MAX_ORDERS (100)
        while order_array.len() < 100 {
            order_array.push(vec!["0".to_string(); 5]);
        }

        // Convert trades to circuit format: [maker_idx, taker_idx, price, size]
        let mut fill_array = Vec::new();

        for trade in trades {
            let maker_idx = order_index_map.get(&trade.maker_order_id).copied().unwrap_or(0);
            let taker_idx = order_index_map.get(&trade.taker_order_id).copied().unwrap_or(0);
            let price_scaled = (trade.price.to_f64().unwrap() * 10000.0) as u64;
            let size_scaled = (trade.size.to_f64().unwrap() * 1e18) as u64;

            fill_array.push(vec![
                maker_idx.to_string(),
                taker_idx.to_string(),
                price_scaled.to_string(),
                size_scaled.to_string(),
            ]);
        }

        // Pad to MAX_FILLS (200)
        while fill_array.len() < 200 {
            fill_array.push(vec!["0".to_string(); 4]);
        }

        // Compute public inputs
        let order_batch_hash = self.compute_order_batch_hash(orders);
        let matching_root = self.compute_matching_root(trades);

        Ok(CircuitInput {
            order_batch_hash,
            matching_root,
            epoch_id: epoch_id.to_string(),
            orders: order_array,
            fills: fill_array,
            num_orders: orders.len().to_string(),
            num_fills: trades.len().to_string(),
        })
    }

    fn generate_witness(&self, epoch_id: u64) -> ClobResult<String> {
        let input_file = format!("{}/order_match_input_{}.json", self.circuit_path, epoch_id);
        let witness_file = format!("{}/witness_{}.wtns", self.circuit_path, epoch_id);

        info!(epoch_id, "Generating witness...");

        let output = Command::new("node")
            .arg(format!("{}/order_match_js/generate_witness.js", self.circuit_path))
            .arg(format!("{}/order_match_js/order_match.wasm", self.circuit_path))
            .arg(&input_file)
            .arg(&witness_file)
            .output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            error!(epoch_id, stderr = %stderr, "Witness generation failed");
            return Err(ClobError::ProofGenerationFailed(stderr.to_string()));
        }

        Ok(witness_file)
    }

    fn generate_proof(&self, epoch_id: u64, witness_file: &str) -> ClobResult<(String, Vec<String>)> {
        info!(epoch_id, "Generating Groth16 proof...");

        let proof_file = format!("{}/proof_{}.json", self.circuit_path, epoch_id);
        let public_file = format!("{}/public_{}.json", self.circuit_path, epoch_id);

        let output = Command::new("snarkjs")
            .arg("groth16")
            .arg("prove")
            .arg(format!("{}/order_match_final.zkey", self.circuit_path))
            .arg(witness_file)
            .arg(&proof_file)
            .arg(&public_file)
            .output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            error!(epoch_id, stderr = %stderr, "Proof generation failed");
            return Err(ClobError::ProofGenerationFailed(stderr.to_string()));
        }

        // Read proof and public signals
        let proof_json = std::fs::read_to_string(&proof_file)?;
        let public_json = std::fs::read_to_string(&public_file)?;
        let public_signals: Vec<String> = serde_json::from_str(&public_json)?;

        Ok((proof_json, public_signals))
    }

    fn compute_order_batch_hash(&self, orders: &[crate::models::Order]) -> String {
        use tiny_keccak::{Hasher, Keccak};
        
        let mut hasher = Keccak::v256();
        for order in orders {
            let id_bytes = self.order_id_to_field_element(&order.id).to_le_bytes();
            hasher.update(&id_bytes);
        }
        
        let mut output = [0u8; 32];
        hasher.finalize(&mut output);
        format!("0x{}", hex::encode(output))
    }

    fn compute_matching_root(&self, trades: &[Trade]) -> String {
        use tiny_keccak::{Hasher, Keccak};
        
        let mut hasher = Keccak::v256();
        for trade in trades {
            hasher.update(&trade.id.as_bytes()[..16]); // Use first 16 bytes of UUID
        }
        
        let mut output = [0u8; 32];
        hasher.finalize(&mut output);
        format!("0x{}", hex::encode(output))
    }

    fn compute_public_inputs_hash(&self, public_signals: &[String]) -> String {
        use tiny_keccak::{Hasher, Keccak};
        
        let mut hasher = Keccak::v256();
        for signal in public_signals {
            hasher.update(signal.as_bytes());
        }
        
        let mut output = [0u8; 32];
        hasher.finalize(&mut output);
        format!("0x{}", hex::encode(output))
    }

    fn order_id_to_field_element(&self, id: &uuid::Uuid) -> u128 {
        let bytes = id.as_bytes();
        u128::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3],
            bytes[4], bytes[5], bytes[6], bytes[7],
            bytes[8], bytes[9], bytes[10], bytes[11],
            bytes[12], bytes[13], bytes[14], bytes[15],
        ])
    }

    async fn store_proof_metadata(&self, proof_data: &OrderMatchProofData) -> ClobResult<()> {
        let key = format!("proof:{}:{}", proof_data.epoch_id, proof_data.market_id);
        let json = serde_json::to_string(proof_data)?;
        self.redis.set(&key, &json).await?;
        Ok(())
    }
}
