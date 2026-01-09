// Copyright 2025 RISC Zero, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use alloy_primitives::{Address, address};
use alloy_sol_types::{SolValue,SolCall, SolType, sol, sol_data, SolEvent};
use anyhow::{Context, Result};
use clap::Parser;
use event_methods::EVENT_GUEST_ELF;
use risc0_steel::{
    Commitment, Contract, SteelVerifier, Event,
    ethereum::{ETH_SEPOLIA_CHAIN_SPEC, ETH_MAINNET_CHAIN_SPEC, EthEvmEnv},
    host::BlockNumberOrTag,
    alloy::{
        network::EthereumWallet,
        providers::{Provider, ProviderBuilder},
    },

};
use risc0_zkvm::{ExecutorEnv, default_executor};
use tracing_subscriber::EnvFilter;
use url::Url;

sol! {
    #[derive(Debug)]
    interface AAvePoolV3 {
        event Borrow(
        address indexed reserve,       // USDT AAvePoolAddress address
        address user,                  // borrower’s address
        address indexed onBehalfOf,    // usually same as user
        uint256 amount,                // amount of USDT borrowed
        uint8 interestRateMode,        // 1 = stable, 2 = variable
        uint256 borrowRate,            // current rate in RAY units
        uint16 indexed referralCode
        );
    }

    struct Journal {
        Commitment commitment;
        uint256 block_number;
        uint256 amount;
    }
}

// const CONTRACT: Address = address!("794a61358D6845594F94dc1DB02A252b5b4814aD"); // op mainnet
const CONTRACT: Address = address!("0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2"); // eth mainnet
/// Address of the caller.
const BORROWER: Address = address!("8f5187de7D4bAB1737e2BEeafbE7F28149506cf4");

/// Simple program to show the use of Ethereum contract data inside the guest.
#[derive(Parser, Debug)]
#[command(about, long_about = None)]
struct Args {
    /// URL of the RPC endpoint
    #[arg(short, long, env = "RPC_URL")]
    rpc_url: Url,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing. In order to view logs, run `RUST_LOG=info cargo run`
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();
    // Parse the command line arguments.
    let args = Args::parse();
    
    let blocks = [24187289, 24188168, 24193875];
    // Create an EVM environment from an RPC endpoint defaulting to the latest block.
    let env_builder = EthEvmEnv::builder()
        .rpc(args.rpc_url)
        .chain_spec(&ETH_MAINNET_CHAIN_SPEC);

    let mut exe_env = ExecutorEnv::builder();
    exe_env.write(&BORROWER).unwrap();
    exe_env.write(&blocks.len()).unwrap();

    for i in 0..blocks.len() {
        let mut env = env_builder.clone().block_number(blocks[i]).build().await?;
        // Preflight the call to prepare the input that is required to execute the function in
        // the guest without RPC access. It also returns the result of the call.
        let event = Event::preflight::<AAvePoolV3::Borrow>(&mut env);
        let logs = event.address(CONTRACT).query().await?;
        log::info!(
            "Contract {} emitted {} events with signature: {}",
            CONTRACT,
            logs.len(),
            AAvePoolV3::Borrow::SIGNATURE,
        );

        println!("log data");
        for (i, log) in logs.iter().enumerate() {
            println!("log{} is {:?}", i, log);
        }

        // Finally, construct the input from the environment.
        let commitment_input1 = env.commitment();
        let input1 = env.into_input().await?;

        if i == 0 {
        }
        exe_env.write(&input1).unwrap();
        
        if blocks.len() > 1 && i < blocks.len() - 1 {
            let mut env_cur = env_builder.clone().block_number(blocks[i + 1]).build().await?;
            SteelVerifier::preflight(&mut env_cur)
            .verify(&commitment_input1)
            .await?;

            let event = Event::preflight::<AAvePoolV3::Borrow>(&mut env_cur);
            let logs = event.address(CONTRACT).query().await?;
            log::info!(
                "Contract {} emitted {} events with signature: {}",
                CONTRACT,
                logs.len(),
                AAvePoolV3::Borrow::SIGNATURE,
            );

            println!("log data");
            for (i, log) in logs.iter().enumerate() {
                println!("log{} is {:?}", i, log);
            }

            let input2 = env_cur.into_input().await?;
            exe_env.write(&input2).unwrap();
            
            // skip the last iteration
            if i == blocks.len() - 2 {
                break;
            }
        }
    }

    println!("Running the guest with the constructed input...");
    let session_info = {
        let env = exe_env.build().context("failed to build executor env")?;
        let exec = default_executor();
        exec.execute(env, EVENT_GUEST_ELF)
            .context("failed to run executor")?
    };

    // The journal should be the ABI encoded commitment.
    // let journals = <Vec::<Journal>>::abi_decode(session_info.journal.as_ref())
    //     .context("failed to decode journal")?;

    let journals = <sol_data::Array<Journal>>::abi_decode(session_info.journal.as_ref())
    .context("failed to decode journals")?;
    println!("Decoded {} journals:", journals.len());
    for (i, journal) in journals.iter().enumerate() {
        println!("Journal[{}]: block_id={}, balance={}", 
            i, journal.block_number, journal.amount);
    }
    
    Ok(())
}
