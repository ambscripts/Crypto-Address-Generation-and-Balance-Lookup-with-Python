import aiohttp, asyncio, hashlib # Imports necessary libraries: aiohttp for asynchronous HTTP requests, asyncio for asynchronous programming, and hashlib for various hashing algorithms. 
#pip install base58
import base58 # Imports base58 library for Base58 encoding/decoding, commonly used in cryptocurrencies. 
#pip install coincurve
from coincurve import PrivateKey, PublicKey # Imports PrivateKey and PublicKey from coincurve for ECC operations. 
#pip install bech32
import bech32 as segwit_addr # Imports bech32 for Bech32 encoding, used in SegWit addresses. 
#pip install pycryptodome
from Crypto.Hash import keccak # Imports keccak from PyCryptodome for Keccak hashing, used in Ethereum. 
#pip install xrpl-py
from xrpl.wallet import Wallet # Imports Wallet from xrpl-py for XRP address and seed generation. 


def sha256(bytes):
    """
    Computes the SHA-256 hash of the input bytes.
    :param bytes: The input bytes to hash.
    :return: The SHA-256 hash digest.
    """
    return hashlib.sha256(bytes).digest()


def ripemd160(bytes):
    """
    Computes the RIPEMD-160 hash of the input bytes.
    :param bytes: The input bytes to hash.
    :return: The RIPEMD-160 hash digest.
    """
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(bytes)
    return ripemd160.digest()


def hash160(bytes):
    """
    Computes the HASH160 (SHA-256 then RIPEMD-160) of the input bytes.
    This is commonly used in Bitcoin address generation.
    :param bytes: The input bytes to hash.
    :return: The HASH160 digest.
    """
    return ripemd160(sha256(bytes))


def doublesha256(bytes):
    """
    Computes the SHA-256 hash twice on the input bytes.
    Used for checksums in Bitcoin-like addresses.
    :param bytes: The input bytes to hash.
    :return: The double SHA-256 hash digest.
    """
    return sha256(sha256(bytes))


def keccak256(bytes):
    """
    Computes the Keccak-256 hash of the input bytes.
    Used primarily in Ethereum address generation.
    :param bytes: The input bytes to hash.
    :return: The Keccak-256 hash digest.
    """
    k = keccak.new(digest_bits=256)
    k.update(bytes)
    return k.digest()


#bitcoin address
def btc_address_way_1(integer):
    """
    Generates Bitcoin addresses (legacy, Bech32) and WIF private key
    from an integer private key using direct point manipulation.
    :param integer: The integer private key (1 to 2^256 - 1). 
    :return: A dictionary containing the legacy address, Bech32 address, and WIF private key.
    """
    # integer minimum value 1, maximum value 115792089237316195423570985008687907852837564279074904382605163141518161494336 
    key_bytes = integer.to_bytes(32, byteorder='big') # Convert integer private key to 32-byte big-endian format. 

    # Generate Wallet Import Format (WIF) for the private key.
    # WIF format: 0x80 (mainnet private key prefix) + private key bytes + 4-byte checksum (first 4 bytes of double SHA256 of prefix+key). 
    WIF = base58.b58encode(b'\x80'+key_bytes+doublesha256(b'\x80'+key_bytes)[:4])
    
    private_key = PrivateKey(key_bytes) # Create a PrivateKey object from the bytes. 
    x, y = private_key.public_key.point() # Get the x and y coordinates of the uncompressed public key. 
    
    # Uncompressed public key format: 0x04 + x-coordinate (32 bytes) + y-coordinate (32 bytes). 
    public_key = b'\x04'+x.to_bytes(32, 'big')+y.to_bytes(32, 'big')
    hash160_public_key = hash160(public_key) # Compute HASH160 of the uncompressed public key. 
    
    # Legacy address format: 0x00 (mainnet P2PKH prefix) + HASH160 of public key + 4-byte checksum. 
    legacy_address = base58.b58encode(b'\x00'+hash160_public_key+doublesha256(b'\x00'+hash160_public_key)[:4])
    
    # Compressed public key format: 0x02 (if y is even) or 0x03 (if y is odd) + x-coordinate (32 bytes). 
    compressed_public_key = (b'\x02' if y % 2 == 0 else b'\x03')+x.to_bytes(32, 'big')
    
    # Bech32 address encoding: 'bc' (Bitcoin prefix) + witness version (0x00) + HASH160 of compressed public key. 
    bech32_address = segwit_addr.encode('bc', 0x00, hash160(compressed_public_key))
    
    return {'legacy': legacy_address.decode(), 'bech32': bech32_address, 'WIF': WIF.decode()}


def btc_address_way_2(integer):
    """
    Generates Bitcoin addresses (legacy, Bech32) and WIF private key
    from an integer private key using `PublicKey.from_secret`.
    :param integer: The integer private key (1 to 2^256 - 1). 
    :return: A dictionary containing the legacy address, Bech32 address, and WIF private key.
    """
    # integer minimum value 1, maximum value 115792089237316195423570985008687907852837564279074904382605163141518161494336 
    key_bytes = integer.to_bytes(32, byteorder='big') # Convert integer private key to 32-byte big-endian format. 
    
    # Generate Wallet Import Format (WIF) for the private key. 
    WIF = base58.b58encode(b'\x80'+key_bytes+doublesha256(b'\x80'+key_bytes)[:4])
    
    # Get the uncompressed public key directly from the secret. 
    public_key = (PublicKey.from_secret(key_bytes)).format(False)
    hash160_public_key = hash160(public_key) # Compute HASH160 of the uncompressed public key. 
    
    # Legacy address generation. 
    legacy_address = base58.b58encode(b'\x00'+hash160_public_key+doublesha256(b'\x00'+hash160_public_key)[:4])
    
    # Get the compressed public key directly from the secret. 
    compressed_public_key = (PublicKey.from_secret(key_bytes)).format(True)
    
    # Bech32 address encoding for SegWit. 
    bech32_address = segwit_addr.encode('bc', 0x00, hash160(compressed_public_key))
    
    return {'legacy': legacy_address.decode(), 'bech32': bech32_address, 'WIF': WIF.decode()}


#litecoin address
def ltc_address(integer):
    """
    Generates Litecoin addresses (legacy, Bech32) and WIF private key
    from an integer private key.
    :param integer: The integer private key (1 to 2^256 - 1). 
    :return: A dictionary containing the legacy address, Bech32 address, and WIF private key.
    """
    # integer minimum value 1, maximum value 115792089237316195423570985008687907852837564279074904382605163141518161494336 
    key_bytes = integer.to_bytes(32, byteorder='big') # Convert integer private key to 32-byte big-endian format. 
    
    # WIF format for Litecoin: 0xB0 (mainnet private key prefix) + private key bytes + 4-byte checksum. 
    WIF = base58.b58encode(b'\xB0'+key_bytes+doublesha256(b'\xB0'+key_bytes)[:4])
    
    private_key = PrivateKey(key_bytes) # Create a PrivateKey object. 
    x, y = private_key.public_key.point() # Get public key coordinates. 
    
    # Uncompressed public key. 
    public_key = b'\x04'+x.to_bytes(32, 'big')+y.to_bytes(32, 'big')
    hash160_public_key = hash160(public_key) # HASH160 of uncompressed public key. 
    
    # Legacy address format for Litecoin: 0x30 (mainnet P2PKH prefix) + HASH160 of public key + 4-byte checksum. 
    legacy_address = base58.b58encode(b'\x30'+hash160_public_key+doublesha256(b'\x30'+hash160_public_key)[:4])
    
    # Compressed public key. 
    compressed_public_key = (b'\x02' if y % 2 == 0 else b'\x03')+x.to_bytes(32, 'big')
    
    # Bech32 address encoding for Litecoin: 'ltc' (Litecoin prefix) + witness version (0x00) + HASH160 of compressed public key. 
    bech32_address = segwit_addr.encode('ltc', 0x00, hash160(compressed_public_key))
    
    return {'legacy': legacy_address.decode(), 'bech32': bech32_address, 'WIF': WIF.decode()}


#zec address
def zec_address(integer):
    """
    Generates Zcash (ZEC) legacy address and WIF private key
    from an integer private key.
    :param integer: The integer private key (1 to 2^256 - 1). 
    :return: A dictionary containing the legacy address and WIF private key.
    """
    # integer minimum value 1, maximum value 115792089237316195423570985008687907852837564279074904382605163141518161494336 
    key_bytes = integer.to_bytes(32, byteorder='big') # Convert integer private key to 32-byte big-endian format. 
    
    # WIF format for Zcash: 0x80 (mainnet private key prefix) + private key bytes + 4-byte checksum. 
    WIF = base58.b58encode(b'\x80'+key_bytes+doublesha256(b'\x80'+key_bytes)[:4])
    
    private_key = PrivateKey(key_bytes) # Create a PrivateKey object. 
    x, y = private_key.public_key.point() # Get public key coordinates. 
    
    # Uncompressed public key. 
    public_key = b'\x04'+x.to_bytes(32, 'big')+y.to_bytes(32, 'big')
    hash160_public_key = hash160(public_key) # HASH160 of uncompressed public key. 
    
    # Legacy address format for Zcash: 0x1c 0xb8 (mainnet P2PKH prefix) + HASH160 of public key + 4-byte checksum. 
    legacy_address = base58.b58encode(b'\x1c\xb8'+hash160_public_key+doublesha256(b'\x1c\xb8'+hash160_public_key)[:4])
    
    return {'legacy': legacy_address.decode(), 'WIF': WIF.decode()}


#dash address
def dash_address(integer):
    """
    Generates Dash legacy address and WIF private key
    from an integer private key.
    :param integer: The integer private key (1 to 2^256 - 1). 
    :return: A dictionary containing the legacy address and WIF private key.
    """
    # integer minimum value 1, maximum value 115792089237316195423570985008687907852837564279074904382605163141518161494336 
    key_bytes = integer.to_bytes(32, byteorder='big') # Convert integer private key to 32-byte big-endian format. 
    
    # WIF format for Dash: 0xcc (mainnet private key prefix) + private key bytes + 4-byte checksum. 
    WIF = base58.b58encode(b'\xcc'+key_bytes+doublesha256(b'\xcc'+key_bytes)[:4])
    
    private_key = PrivateKey(key_bytes) # Create a PrivateKey object. 
    x, y = private_key.public_key.point() # Get public key coordinates. 
    
    # Uncompressed public key. 
    public_key = b'\x04'+x.to_bytes(32, 'big')+y.to_bytes(32, 'big')
    hash160_public_key = hash160(public_key) # HASH160 of uncompressed public key. 
    
    # Legacy address format for Dash: 'L' (mainnet P2PKH prefix, which is 0x4c or ASCII 'L') + HASH160 of public key + 4-byte checksum. 
    legacy_address = base58.b58encode(b'L'+hash160_public_key+doublesha256(b'L'+hash160_public_key)[:4])
    
    return {'legacy': legacy_address.decode(), 'WIF': WIF.decode()}


#ethereum address
def ethereum_address(integer):
    """
    Generates an Ethereum address and a "WIF-like" private key (though WIF is not standard for Ethereum)
    from an integer private key.
    :param integer: The integer private key (1 to 2^256 - 1). 
    :return: A dictionary containing the Ethereum address and WIF-like private key.
    """
    # integer minimum value 1, maximum value 115792089237316195423570985008687907852837564279074904382605163141518161494336 
    key_bytes = integer.to_bytes(32, byteorder='big') # Convert integer private key to 32-byte big-endian format. 
    
    # WIF-like format (using Bitcoin's 0x00 prefix, not standard for ETH). 
    WIF = base58.b58encode(b'\x00'+key_bytes+doublesha256(b'\x00'+key_bytes)[:4])
    
    pk = PrivateKey(key_bytes) # Create a PrivateKey object. 
    x, y = pk.public_key.point() # Get public key coordinates. 
    
    # Compute Keccak-256 hash of the uncompressed public key (excluding the 0x04 prefix), then take the last 20 bytes. 
    keccak_256 = keccak256((b'\x04'+x.to_bytes(32, 'big')+y.to_bytes(32, 'big'))[1:])[-20:]
    
    # Ethereum address format: '0x' + last 20 bytes of Keccak-256 hash of the public key. 
    legacy_address = '0x'+keccak_256.hex()
    
    return {'address': legacy_address, 'WIF': WIF.decode()}


#bch address
def polymod(values):
    """
    Computes the BCH (Bitcoin Cash) Bech32 checksum.
    This is a helper function for the Bech32 encoding used in BCH.
    :param values: A list of 5-bit integers. 
    :return: The calculated checksum.
    """
    chk = 1
    generator = [(0x01, 0x98f2bc8e61),(0x02, 0x79b76d99e2),(0x04, 0xf33e5fb3c4),(0x08, 0xae2eabe2a8),(0x10, 0x1e4f43e470)]
    for value in values:
        top = chk >> 35 # Get the 5 most significant bits. 
        chk = ((chk & 0x07ffffffff) << 5) ^ value # Shift left by 5 bits and XOR with the current value. 
        for i in generator: # Apply XOR with generator polynomials based on 'top' bits. 
            if top & i[0] != 0:
                chk ^= i[1]
    return chk ^ 1

def calculate_checksum(prefix, payload):
    """
    Calculates the checksum for a Bitcoin Cash (BCH) address.
    :param prefix: The human-readable part of the address (e.g., 'bitcoincash'). 
    :param payload: The data part of the address (5-bit integers). 
    :return: A list of 5-bit integers representing the checksum.
    """
    # Combine prefix (converted to 5-bit ASCII values), a separator (0), payload, and 8 zero padding bytes. 
    poly = polymod([ord(x) & 0x1f for x in prefix]+[0]+payload+[0,0,0,0,0,0,0,0])
    # Extract 8 5-bit chunks from the polymod result for the checksum. 
    return [((poly >> 5 * (7 - i)) & 0x1f) for i in range(8)]

def b32encode(inputs):
    """
    Encodes a list of 5-bit integers into a Bech32 string using the Bitcoin Cash character set.
    :param inputs: A list of 5-bit integers. 
    :return: The Bech32 encoded string.
    """
    out = ''
    # Map 5-bit values to the specific BCH Bech32 character set. 
    for x in inputs:
        out += 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'[x]
    return out

def bitcoin_legacy_to_bch(legacy):
    """
    Converts a Bitcoin legacy address to a Bitcoin Cash (BCH) address.
    :param legacy: The Bitcoin legacy address string. 
    :return: A dictionary containing the BCH address.
    """
    decoded = base58.b58decode_check(legacy.encode()) # Decode the Base58Check Bitcoin legacy address. 
    
    # Prepare payload: 0 (version byte for P2PKH) + decoded address bytes (excluding original version byte). 
    payload = [0]+[x for x in decoded[1:]]
    
    # Convert the 8-bit payload to 5-bit chunks for Bech32 encoding. 
    payload = segwit_addr.convertbits(payload, 8, 5)
    
    check = calculate_checksum('bitcoincash', payload) # Calculate the BCH-specific Bech32 checksum. 
    
    # Construct the BCH address: 'bitcoincash' prefix + ':' + encoded payload and checksum. 
    return {'address': 'bitcoincash'+':'+b32encode(payload+check)}


#xrp address
def xrp_address(integer):
    """
    Generates an XRP address and SEED from an integer entropy.
    :param integer: The integer entropy (0 to 2^128 - 1). 
    :return: A dictionary containing the XRP classic address and seed.
    """
    # integer minimum value 0, maximum value 340282366920938463463374607431768211455 
    key_bytes = integer.to_bytes(16, byteorder='big') # Convert integer entropy to 16-byte big-endian format. 
    
    # Generate an XRP wallet from the hexadecimal representation of the key bytes (entropy). 
    wallet = Wallet.from_entropy(key_bytes.hex())
    
    return {'address': wallet.classic_address, 'SEED': wallet.seed} # Return the classic address and the wallet seed.


#bitcoin balance
async def get_btc_balances(addresses):
    """
    Asynchronously retrieves the balances for multiple Bitcoin addresses using blockchain.info API.
    :param addresses: A list of Bitcoin addresses (Bech32 or legacy). 
    :return: A dictionary where keys are addresses and values are their balance information.
    """
    try:
        async with aiohttp.ClientSession() as session: # Create an aiohttp client session. 
            # Make a GET request to blockchain.info balance API, joining addresses with '|'. 
            async with session.get('https://blockchain.info/balance', params={'active': '|'.join(addresses)}) as response:
                return await response.json() # Return the JSON response. 
    except Exception as e:
        print(e) # Print any exceptions that occur.


#litecoin balance
async def get_ltc_balance(address):
    """
    Asynchronously retrieves the balance for a single Litecoin address.
    :param address: The Litecoin address. 
    :return: A tuple containing the address, final balance, and transaction count, or just the address and balance if no txids.
    """
    try:
        async with aiohttp.ClientSession() as session: # Create an aiohttp client session. 
            # Make a GET request to the Litecoin Atomic Wallet API. 
            async with session.get('https://litecoin.atomicwallet.io/api/v2/address/'+address, params={}) as response:
                result = await response.json() # Get the JSON response. 
                
                # Check if 'txids' key exists in the result. 
                if( 'txids' in result ):
                    # Return address, evaluated balance, and txids. 
                    return address, eval(result['balance']), result['txids']
                else:
                    # Return address, evaluated balance, and 0 for txids if not present. 
                    return address, eval(result['balance']), 0
    except Exception as e:
        print(e) # Print any exceptions that occur.


async def get_ltc_balances(addresses):
    """
    Asynchronously retrieves balances for multiple Litecoin addresses concurrently.
    :param addresses: A list of Litecoin addresses. 
    :return: A dictionary where keys are addresses and values are dictionaries with 'final_balance' and 'tx'.
    """
    try:
        # Use asyncio.gather to run get_ltc_balance for all addresses concurrently. 
        balances = await asyncio.gather(*[get_ltc_balance(x) for x in addresses])
        result = {} # Initialize an empty dictionary for results. 
        for x in balances: # Iterate through the results from get_ltc_balance. 
            result[x[0]] = {'final_balance': x[1], 'tx': x[2]} # Populate the result dictionary. 
        return result # Return the aggregated balances. 
    except Exception as e:
        print(e) # Print any exceptions that occur.


#xrp balance
async def get_xrp_balance(address):
    """
    Asynchronously retrieves the balance for a single XRP address using the Ripple API.
    :param address: The XRP classic address. 
    :return: The XRP balance in XRP units, or an error message if the account data is not found.
    """
    try:
        async with aiohttp.ClientSession() as session: # Create an aiohttp client session. 
            # Make a POST request to the Ripple API for account_info. 
            async with session.post('https://s1.ripple.com:51234/', json={"method": "account_info","params": [{"account": address}]}, headers={'Content-Type': 'application/json'}) as response:
                result = await response.json() # Get the JSON response. 
                
                # Check if 'account_data' is present in the result. 
                if( 'account_data' in result['result'] ):
                    # Return the balance, converting from drops to XRP (1 XRP = 1,000,000 drops). 
                    return eval(result['result']['account_data']['Balance'])/1000000
                else:
                    return result['result']['error'] # Return the error message if account_data is not found. 
    except Exception as e:
        print(e) # Print any exceptions that occur.


if __name__ == "__main__":
    # This block demonstrates the usage of the address generation and balance checking functions.
    print('--------- Address generation:')
    integer_key = 777 # Example integer private key.
    
    # Generate Bitcoin addresses using btc_address_way_1.
    btc = btc_address_way_1(integer_key)
    print('\nBitcoin','- Key:',integer_key,'\n',btc)
    
    # Generate Litecoin addresses.
    ltc = ltc_address(integer_key)
    print('\nLitecoin','- Key:',integer_key,'\n',ltc)
    
    # Generate Zcash addresses.
    zec = zec_address(integer_key)
    print('\nZEC','- Key:',integer_key,'\n',zec)
    
    # Generate Dash addresses.
    dash = dash_address(integer_key)
    print('\nDASH','- Key:',integer_key,'\n',dash)
    
    # Generate Ethereum addresses.
    eth = ethereum_address(integer_key)
    print('\nETH','- Key:',integer_key,'\n',eth)
    
    # Convert Bitcoin legacy address to Bitcoin Cash address.
    bch = bitcoin_legacy_to_bch(btc['legacy'])
    print('\nBCH','- Key:',integer_key,'\n',bch)
    
    # Generate XRP addresses.
    xrp = xrp_address(integer_key)
    print('\nXRP','- Key:',integer_key,'\n',xrp)
    
    print('\n--------- Address balance checking:')
    
    # Prepare a list of Bitcoin Bech32 addresses for balance checking.
    btc_addresses = [btc_address_way_1(i)['bech32'] for i in range(100000000,100000000+6)]
    print('\n- Checking balance for btc addresses:')
    print(btc_addresses)
    print('\n>> BTC balances:')
    # Run the asynchronous function to get BTC balances.
    # Note: This requires running within an asyncio event loop (e.g., in an async function or using asyncio.run()).
    # For a simple script, outside of an async function, you'd typically use:
    # import asyncio
    # print(asyncio.run(get_btc_balances(btc_addresses)))
    # The current 'await' here will only work if this __main__ block is part of an async context.
    # For standalone execution, it should be wrapped in an async function and run with asyncio.run().
    print(await get_btc_balances(btc_addresses))
    
    # Prepare a list of Litecoin Bech32 addresses for balance checking.
    ltc_addresses = [ltc_address(i)['bech32'] for i in range(100000000,100000000+6)]
    print('\n- Checking balance for ltc addresses:')
    print(ltc_addresses)
    print('\n>> LTC balances:')
    # Run the asynchronous function to get LTC balances.
    # Similar to BTC, this 'await' needs an async context or asyncio.run().
    print(await get_ltc_balances(ltc_addresses))
    
    # Specify a single XRP address for balance checking.
    xrp_address = 'rfL1mn4VTCoHdhHhHMwqpShCFUaDBRk6Z5'
    print('\n- Checking balance for xrp address:')
    print(xrp_address)
    print('\n>> XRP balance:')
    # Run the asynchronous function to get XRP balance.
    # Similar to BTC and LTC, this 'await' needs an async context or asyncio.run().
    print(await get_xrp_balance(xrp_address))