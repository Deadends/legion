// Real Halo2 proof generation
use crate::auth_circuit::AuthCircuit;
use anyhow::{anyhow, Result};
use halo2_proofs::{
    plonk::{
        create_proof, keygen_pk, keygen_vk, verify_proof, ProvingKey, SingleVerifier, VerifyingKey,
    },
    poly::commitment::Params,
    transcript::{Blake2bRead, Blake2bWrite, Challenge255},
};
use pasta_curves::{vesta, Fp};
use rand::rngs::OsRng;
use std::io::Cursor;

pub struct ProofGenerator {
    pub params: Params<vesta::Affine>,
    pub vk: Option<VerifyingKey<vesta::Affine>>,
    pub pk: Option<ProvingKey<vesta::Affine>>,
    k: u32,
}

impl ProofGenerator {
    /// Server-side: Verifier-only mode (no key generation at startup)
    pub fn new_verifier_only() -> Self {
        println!("✅ ProofGenerator initialized in VERIFIER-ONLY mode");
        println!("   → Server will NOT generate proofs (zero-knowledge!)");
        println!("   → Keys will be generated on-demand for verification");

        // Dummy params - will be replaced when verifying
        let params = Params::<vesta::Affine>::new(14);

        Self {
            params,
            vk: None,
            pk: None,
            k: 14,
        }
    }

    /// Client-side: Full mode with key generation
    pub fn new(k: u32) -> Result<Self> {
        println!("⏳ [1/4] Initializing ProofGenerator with k={}...", k);
        let params = Self::load_or_generate_params(k)?;
        println!("✅ [1/4] Params ready");

        println!("⏳ [2/4] Creating dummy circuit for key generation...");
        let dummy_circuit = AuthCircuit::default();
        println!("✅ [2/4] Dummy circuit created");

        println!("⏳ [3/4] Generating verifying key (VK)...");
        let vk = keygen_vk(&params, &dummy_circuit)
            .map_err(|e| anyhow!("VK generation failed: {}", e))?;
        println!("✅ [3/4] VK generated");

        println!("⏳ [4/4] Generating proving key (PK)...");
        let pk = keygen_pk(&params, vk.clone(), &dummy_circuit)
            .map_err(|e| anyhow!("PK generation failed: {}", e))?;
        println!("✅ [4/4] PK generated");

        println!("✅ ✅ ✅ Total initialization complete");

        Ok(Self {
            params,
            vk: Some(vk),
            pk: Some(pk),
            k,
        })
    }

    /// WASM-optimized: Create from params bytes, generate keys
    pub fn from_params_bytes(k: u32, params_bytes: &[u8]) -> Result<Self> {
        #[cfg(target_arch = "wasm32")]
        {
            use wasm_bindgen::prelude::*;
            #[wasm_bindgen]
            extern "C" {
                #[wasm_bindgen(js_namespace = console)]
                fn log(s: &str);
            }
            log(&format!(
                "⏳ Loading params from bytes ({} bytes)...",
                params_bytes.len()
            ));
        }

        let params = Params::read(&mut Cursor::new(params_bytes))?;

        #[cfg(target_arch = "wasm32")]
        {
            use wasm_bindgen::prelude::*;
            #[wasm_bindgen]
            extern "C" {
                #[wasm_bindgen(js_namespace = console)]
                fn log(s: &str);
            }
            log("✅ Params loaded");
            log("⏳ Generating verifying key (VK) - this takes ~10-15s...");
        }

        let dummy_circuit = AuthCircuit::default();
        let vk = keygen_vk(&params, &dummy_circuit)
            .map_err(|e| anyhow!("VK generation failed: {}", e))?;

        #[cfg(target_arch = "wasm32")]
        {
            use wasm_bindgen::prelude::*;
            #[wasm_bindgen]
            extern "C" {
                #[wasm_bindgen(js_namespace = console)]
                fn log(s: &str);
            }
            log("✅ VK generated");
            log("⏳ Generating proving key (PK) - this takes ~10-15s...");
        }

        let pk = keygen_pk(&params, vk.clone(), &dummy_circuit)
            .map_err(|e| anyhow!("PK generation failed: {}", e))?;

        #[cfg(target_arch = "wasm32")]
        {
            use wasm_bindgen::prelude::*;
            #[wasm_bindgen]
            extern "C" {
                #[wasm_bindgen(js_namespace = console)]
                fn log(s: &str);
            }
            log("✅ PK generated");
        }

        Ok(Self {
            params,
            vk: Some(vk),
            pk: Some(pk),
            k,
        })
    }

    #[cfg(feature = "redis")]
    fn load_or_generate_params(k: u32) -> Result<Params<vesta::Affine>> {
        use redis::Commands;
        let client = redis::Client::open("redis://127.0.0.1:6379/")?;
        let mut conn = client.get_connection()?;
        let key = format!("legion:params:k{}", k);

        if let Ok(bytes) = conn.get::<_, Vec<u8>>(&key) {
            if !bytes.is_empty() {
                println!("✅ Loading params from Redis ({} bytes)", bytes.len());
                match Params::read(&mut Cursor::new(&bytes)) {
                    Ok(params) => return Ok(params),
                    Err(e) => {
                        println!("⚠️  Corrupted cache, regenerating: {}", e);
                        let _: () = conn.del(&key)?;
                    }
                }
            }
        }

        println!("⏳ Generating params (30s, caching to Redis)...");
        let params = Params::new(k);
        let mut buf = Vec::new();
        params.write(&mut buf)?;
        let _: () = conn.set(&key, &buf)?;
        println!("💾 Cached {} bytes to Redis", buf.len());
        Ok(params)
    }

    #[cfg(not(feature = "redis"))]
    fn load_or_generate_params(k: u32) -> Result<Params<vesta::Affine>> {
        #[cfg(target_arch = "wasm32")]
        {
            // WASM: Generate params in-memory (no filesystem)
            println!("⏳ Generating params in-memory for WASM (k={})...", k);
            Ok(Params::new(k))
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            use std::fs::{self, File};
            let path = format!("./params/k{}.params", k);

            if let Ok(mut file) = File::open(&path) {
                println!("✅ Loading params from {}", path);
                return Ok(Params::read(&mut file)?);
            }

            println!("⏳ Generating params (30s, caching locally)...");
            let params = Params::new(k);
            fs::create_dir_all("./params")?;
            let mut file = File::create(&path)?;
            params.write(&mut file)?;
            println!("💾 Cached to {}", path);
            Ok(params)
        }
    }

    pub fn setup(&mut self, _circuit: &AuthCircuit) -> Result<()> {
        // Keys already generated at startup
        if self.pk.is_some() && self.vk.is_some() {
            println!("✅ Using pre-generated keys");
            return Ok(());
        }
        Err(anyhow!("Keys not initialized - this should not happen"))
    }

    pub fn generate_proof(&self, circuit: AuthCircuit, public_inputs: &[Fp]) -> Result<Vec<u8>> {
        println!("🔍 DEBUG: generate_proof() called");
        println!("🔍 DEBUG: pk.is_some() = {}", self.pk.is_some());

        let pk = self
            .pk
            .as_ref()
            .ok_or_else(|| anyhow!("Proving key not initialized"))?;

        println!("🔍 DEBUG: Starting create_proof...");
        println!("💾 Allocating proof buffer on heap...");

        #[cfg(not(target_arch = "wasm32"))]
        let start = std::time::Instant::now();

        // Box circuit to force heap allocation
        let boxed_circuit = Box::new(circuit);
        let mut transcript = Blake2bWrite::<_, vesta::Affine, Challenge255<_>>::init(vec![]);

        create_proof(
            &self.params,
            pk,
            &[*boxed_circuit],
            &[&[public_inputs]],
            OsRng,
            &mut transcript,
        )?;

        let proof = transcript.finalize();

        #[cfg(not(target_arch = "wasm32"))]
        println!(
            "✅ Proof generated in {:?}, size: {} bytes",
            start.elapsed(),
            proof.len()
        );

        #[cfg(target_arch = "wasm32")]
        println!("✅ Proof generated, size: {} bytes", proof.len());

        Ok(proof)
    }

    pub fn verify_proof(&self, proof: &[u8], public_inputs: &[Fp]) -> Result<bool> {
        // Generate VK on-demand if not present (verifier-only mode)
        let vk = if let Some(vk) = &self.vk {
            vk.clone()
        } else {
            println!("⏳ Generating verifying key on-demand...");
            let dummy_circuit = AuthCircuit::default();
            keygen_vk(&self.params, &dummy_circuit)
                .map_err(|e| anyhow!("VK generation failed: {}", e))?
        };

        let strategy = SingleVerifier::new(&self.params);
        let mut transcript = Blake2bRead::<_, vesta::Affine, Challenge255<_>>::init(proof);

        match verify_proof(
            &self.params,
            &vk,
            strategy,
            &[&[public_inputs]],
            &mut transcript,
        ) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Serialize params to bytes for caching
    pub fn get_params_bytes(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        self.params.write(&mut buf)?;
        Ok(buf)
    }
}
