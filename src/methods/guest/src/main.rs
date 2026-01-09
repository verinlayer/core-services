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

#![allow(unused_doc_comments)]
#![no_main]

use alloy_primitives::{Address, address, U256};
// use alloy_sol_types::sol;
use alloy_sol_types::{SolCall, SolValue, sol};
use risc0_steel::{
    Contract, SteelVerifier, Commitment, Event,
    ethereum::{ETH_SEPOLIA_CHAIN_SPEC, EthEvmInput, ETH_MAINNET_CHAIN_SPEC},
};
use risc0_zkvm::guest::env;

risc0_zkvm::guest::entry!(main);

/// Specify the function to call using the [`sol!`] macro.
/// This parses the Solidity syntax to generate a struct that implements the `SolCall` trait.
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
const CALLER: Address = address!("884120024D515544Ac0Fd925F228dd084f0A75Cd");
const USDC: Address = address!("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48");

fn main() {
    //read borrower address
    let borrower : Address = env::read();
    // Read the input from the guest environment.
    let number_inputs: u64 = env::read();

    println!("blocks len : {number_inputs}");

    let mut journals: Vec<Journal> = Vec::with_capacity(number_inputs.try_into().unwrap());

    for i in 0..number_inputs {
        let input: EthEvmInput = env::read();
    
        // Converts the input into a `EvmEnv` for execution. It checks that the state matches the state
        // root in the header provided in the input.
        let env_prev = input.into_env(&ETH_MAINNET_CHAIN_SPEC);

        let event = Event::new::<AAvePoolV3::Borrow>(&env_prev);
        let logs = event.address(CONTRACT).query();

        // Process the events.
        let value = logs.iter().map(|log| {
            if log.data.user == borrower {
                if log.data.reserve == USDC {
                    log.data.amount
                }
                else {
                    U256::from(0)
                }
            } else {
                U256::from(0)
            }
        })
        .sum::<U256>();
        println!("borrow value: {}", value);

        // only push the first return of env to journal, the second one is put the the else
        if i == 0 {
            journals.push(Journal{
                    commitment: env_prev.commitment().clone(),
                    amount: value,
                    block_number: env_prev.commitment().clone().id,
                });
        }

        if number_inputs == 1{
            env::commit_slice(&journals.abi_encode());
        }
        else {
            // Prepare the second `EvmEnv` for execution.  It corresponds to the recent EVM state.
            let input: EthEvmInput = env::read();
            let env_cur = input.into_env(&ETH_MAINNET_CHAIN_SPEC);
            // Verify that the older EVM state is valid wrt the recent EVM state.
            // We initialize the SteelVerifier with the recent state, to check the previous commitment.
            SteelVerifier::new(&env_cur).verify(env_prev.commitment());
        
            let event = Event::new::<AAvePoolV3::Borrow>(&env_cur);
            let logs = event.address(CONTRACT).query();

            // Process the events.
            let value = logs.iter().map(|log| {
            if log.data.user == borrower {
                if log.data.reserve == USDC {
                    log.data.amount
                }
                else {
                    U256::from(0)
                }
            } else {
                U256::from(0)
            }
        }).sum::<U256>();
            println!("borrow value: {}", value);
            journals.push(Journal{
                    commitment: env_cur.commitment().clone(),
                    amount: value,
                    block_number: env_cur.commitment().clone().id,
                });

            if i == number_inputs - 2 {
                println!("number of journals: {}", journals.len());
                for (i, journal) in journals.iter().enumerate() {
                    println!("  Journal[{}]:", i);
                    println!("    commitment: {:?}", journal.commitment);
                    println!("    balance: {}", journal.amount);
                }
                env::commit_slice(&journals.abi_encode());
                break;
            }
            
        }
    
    }

}
