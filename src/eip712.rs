use anyhow::Result;
use ethers::{
    prelude::*,
    types::{Address, Signature, H256, U256},
    utils::keccak256,
};
use serde::{Deserialize, Serialize};

/// EIP-712 domain separator
#[derive(Debug, Clone)]
pub struct Eip712Domain {
    pub name: String,
    pub version: String,
    pub chain_id: u64,
    pub verifying_contract: Address,
}

impl Eip712Domain {
    pub fn new(chain_id: u64, verifying_contract: Address) -> Self {
        Self {
            name: "Predifi CLOB".to_string(),
            version: "1".to_string(),
            chain_id,
            verifying_contract,
        }
    }

    /// Compute EIP-712 domain separator hash
    pub fn hash(&self) -> H256 {
        let domain_type_hash = keccak256(
            "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
        );

        let name_hash = keccak256(self.name.as_bytes());
        let version_hash = keccak256(self.version.as_bytes());

        let encoded = ethers::abi::encode(&[
            ethers::abi::Token::FixedBytes(domain_type_hash.to_vec()),
            ethers::abi::Token::FixedBytes(name_hash.to_vec()),
            ethers::abi::Token::FixedBytes(version_hash.to_vec()),
            ethers::abi::Token::Uint(U256::from(self.chain_id)),
            ethers::abi::Token::Address(self.verifying_contract),
        ]);

        H256::from_slice(&keccak256(encoded))
    }
}

/// EIP-712 typed order for signing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Eip712Order {
    pub order_id: U256,
    pub market_id: U256,
    pub maker: Address,
    pub side: u8,    // 0 = BUY, 1 = SELL
    pub price: U256, // Basis points (0-10000)
    pub size: U256,
    pub nonce: U256,
    pub expiry: U256, // Unix timestamp
}

impl Eip712Order {
    /// Get the EIP-712 type hash for Order
    pub fn type_hash() -> H256 {
        H256::from_slice(&keccak256(
            "Order(uint256 orderId,uint256 marketId,address maker,uint8 side,uint256 price,uint256 size,uint256 nonce,uint256 expiry)"
        ))
    }

    /// Compute the struct hash
    pub fn struct_hash(&self) -> H256 {
        let encoded = ethers::abi::encode(&[
            ethers::abi::Token::FixedBytes(Self::type_hash().as_bytes().to_vec()),
            ethers::abi::Token::Uint(self.order_id),
            ethers::abi::Token::Uint(self.market_id),
            ethers::abi::Token::Address(self.maker),
            ethers::abi::Token::Uint(U256::from(self.side)),
            ethers::abi::Token::Uint(self.price),
            ethers::abi::Token::Uint(self.size),
            ethers::abi::Token::Uint(self.nonce),
            ethers::abi::Token::Uint(self.expiry),
        ]);

        H256::from_slice(&keccak256(encoded))
    }

    /// Compute the EIP-712 digest to be signed
    pub fn digest(&self, domain: &Eip712Domain) -> H256 {
        let domain_separator = domain.hash();
        let struct_hash = self.struct_hash();

        let encoded = [
            &[0x19, 0x01],
            domain_separator.as_bytes(),
            struct_hash.as_bytes(),
        ]
        .concat();

        H256::from_slice(&keccak256(encoded))
    }

    /// Sign the order with a wallet
    pub async fn sign(&self, domain: &Eip712Domain, wallet: &LocalWallet) -> Result<Signature> {
        let digest = self.digest(domain);
        let signature = wallet.sign_hash(digest)?;
        Ok(signature)
    }

    /// Verify the order signature
    pub fn verify_signature(
        &self,
        domain: &Eip712Domain,
        signature: &Signature,
    ) -> Result<Address> {
        let digest = self.digest(domain);
        let recovered = signature.recover(digest)?;
        Ok(recovered)
    }

    /// Verify that the signature matches the maker address
    pub fn verify(&self, domain: &Eip712Domain, signature: &Signature) -> Result<bool> {
        let recovered = self.verify_signature(domain, signature)?;
        Ok(recovered == self.maker)
    }
}

/// EIP-712 signer for creating and verifying order signatures
pub struct Eip712Signer {
    domain: Eip712Domain,
    wallet: Option<LocalWallet>,
}

impl Eip712Signer {
    pub fn new(
        chain_id: u64,
        contract_address: Address,
        private_key: Option<&str>,
    ) -> Result<Self> {
        let wallet = if let Some(key) = private_key {
            Some(key.parse()?)
        } else {
            None
        };

        Ok(Self {
            domain: Eip712Domain::new(chain_id, contract_address),
            wallet,
        })
    }

    /// Sign an order (requires wallet)
    pub async fn sign_order(&self, order: &Eip712Order) -> Result<Signature> {
        let wallet = self
            .wallet
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("No wallet configured"))?;

        order.sign(&self.domain, wallet).await
    }

    /// Verify an order signature
    pub fn verify_order(&self, order: &Eip712Order, signature: &Signature) -> Result<bool> {
        order.verify(&self.domain, signature)
    }

    /// Recover signer address from signature
    pub fn recover_signer(&self, order: &Eip712Order, signature: &Signature) -> Result<Address> {
        order.verify_signature(&self.domain, signature)
    }

    /// Get domain separator
    pub fn domain(&self) -> &Eip712Domain {
        &self.domain
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethers::signers::Signer;

    #[tokio::test]
    async fn test_eip712_signing() {
        // Create a test wallet
        let wallet = LocalWallet::new(&mut rand::thread_rng());
        let chain_id = 84532; // Base Sepolia
        let contract: Address = "0x1234567890123456789012345678901234567890"
            .parse()
            .unwrap();

        let signer = Eip712Signer::new(chain_id, contract, None).unwrap();

        // Create a test order
        let order = Eip712Order {
            order_id: U256::from(1),
            market_id: U256::from(1000000),
            maker: wallet.address(),
            side: 0,                 // BUY
            price: U256::from(5000), // 50%
            size: U256::from(100),
            nonce: U256::from(1),
            expiry: U256::from(1700000000),
        };

        // Sign the order
        let signature = order.sign(&signer.domain, &wallet).await.unwrap();

        // Verify the signature
        assert!(order.verify(&signer.domain, &signature).unwrap());

        // Recover signer
        let recovered = order.verify_signature(&signer.domain, &signature).unwrap();
        assert_eq!(recovered, wallet.address());
    }

    #[test]
    fn test_domain_separator() {
        let domain = Eip712Domain::new(
            1,
            "0x1234567890123456789012345678901234567890"
                .parse()
                .unwrap(),
        );

        let hash = domain.hash();
        assert_eq!(hash.as_bytes().len(), 32);
    }
}
