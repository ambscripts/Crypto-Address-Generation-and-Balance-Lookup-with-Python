# Crypto Address Generation and Balance Lookup

## Overview

This project provides a set of Python functions to generate various cryptocurrency addresses (Bitcoin, Litecoin, Zcash, Dash, Ethereum, Bitcoin Cash, XRP) from a given integer private key. Additionally, it includes asynchronous functions to check the balances of Bitcoin, Litecoin, and XRP addresses using public blockchain APIs. This tool can be useful for developers, researchers, or anyone interested in understanding or working with cryptocurrency address generation and basic balance lookups programmatically.

### Features

- ✅ Generates Bitcoin (legacy and Bech32) addresses.
- ✅ Generates Litecoin (legacy and Bech32) addresses.
- ✅ Generates Zcash (legacy) addresses.
- ✅ Generates Dash (legacy) addresses.
- ✅ Generates Ethereum addresses.
- ✅ Converts Bitcoin legacy addresses to Bitcoin Cash addresses.
- ✅ Generates XRP addresses and seeds.
- ✅ Computes SHA-256, RIPEMD-160, HASH160, double SHA-256, and Keccak-256 hashes.
- ✅ Asynchronously retrieves Bitcoin address balances via Blockchain.info API.
- ✅ Asynchronously retrieves Litecoin address balances via Atomic Wallet API.
- ✅ Asynchronously retrieves XRP address balances via Ripple API.

### Requirements

    pip install aiohttp
    pip install base58
    pip install coincurve
    pip install bech32
    pip install pycryptodome
    pip install xrpl-py

### Getting Started

    python crypto.py

The script will:

1. Generate various cryptocurrency addresses (Bitcoin, Litecoin, Zcash, Dash, Ethereum, Bitcoin Cash, XRP) based on a sample integer private key (777).

2. Print the generated addresses and their associated private key formats (e.g., WIF).

3. Proceed to check the balances for a predefined set of Bitcoin, Litecoin, and a specific XRP address by making asynchronous API calls.

4. Display the retrieved balances for the checked addresses.

### License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
