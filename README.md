# ERC20 Example

**An example that uses the ERC20 interface's `balanceOf` method.**

## Prerequisites

To get started, you need to have Rust installed. If you haven't done so, follow the instructions [here][install-rust].

Next, you will also need to have the `cargo-risczero` tool installed following the instructions [here][install-risczero].

You'll also need access to an Ethereum Sepolia RPC endpoint. You can for example use [ethereum-sepolia-rpc.publicnode.com](https://ethereum-sepolia-rpc.publicnode.com) or a commercial RPC provider like [Alchemy](https://www.alchemy.com/).

## Run the example

To run the example, on Sepolia, execute the following command:

```bash
RPC_URL=https://ethereum-sepolia-rpc.publicnode.com RUST_LOG=info cargo run --release
```

