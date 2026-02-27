use bip39::Mnemonic;
use blake2b_simd::Params;
use pasta_curves::group::ff::{FromUniformBytes, PrimeField};
use hex::decode;
use orchard::keys::{SpendingKey, FullViewingKey, IncomingViewingKey, Scope};
use zcash_primitives::zip32::AccountId;
use std::{env, process};
use subtle::CtOption;
use zcash_keys::keys::{UnifiedFullViewingKey, UnifiedIncomingViewingKey};
use zcash_address::unified::{Encoding, Address as UnifiedAddress, Receiver};



fn main() {

 println!("\nTHE ORCHARD MAP\n\n");
 println!("\x1b[34m+---------------------+\x1b[0m");
    println!("\x1b[34m| Orchard             |\x1b[0m");
    println!("\x1b[34m| spending key        |\x1b[0m");
    println!("\x1b[34m| (spending key)      |\x1b[0m");
    println!("\x1b[34m| sk                  |\x1b[0m");
    println!("\x1b[34m+---------------------+\x1b[0m");
    println!("          \x1b[37m|\x1b[0m");
    println!("          \x1b[37mv\x1b[0m");
    println!("\x1b[32m+------------------------------------+\x1b[0m");
    println!("\x1b[32m| Spend authorizing key              |\x1b[0m");
    println!("\x1b[32m| (spend authorising key - private)  |\x1b[0m");
    println!("\x1b[32m| ask                                |\x1b[0m");
    println!("\x1b[32m+------------------------------------+\x1b[0m");
    println!("          \x1b[37m|\x1b[0m");
    println!("          \x1b[37mv\x1b[0m");
    println!("\x1b[33m+-----------------------------------------+\x1b[0m");
    println!("\x1b[33m| Full viewing key                       |\x1b[0m");
    println!("\x1b[33m| (ak: spend-validating key - public,    |\x1b[0m");
    println!("\x1b[33m|  nk: nullifier-deriving key,           |\x1b[0m");
    println!("\x1b[33m|  rivk: raw incoming viewing key)       |\x1b[0m");
    println!("\x1b[33m| (ak, nk, rivk)                         |\x1b[0m");
    println!("\x1b[33m+-----------------------------------------+\x1b[0m");
    println!("          \x1b[37m|\x1b[0m");
    println!("          \x1b[37m+\x1b[0m------------------------------\x1b[37m+\x1b[0m------------------------------\x1b[37m+\x1b[0m");
    println!("          \x1b[37m|\x1b[0m                              \x1b[37m|\x1b[0m                              \x1b[37m|\x1b[0m");
    println!("          \x1b[37mv\x1b[0m                              \x1b[37mv\x1b[0m                              \x1b[37mv\x1b[0m");
    println!("\x1b[35m+--------------------------+\x1b[0m   \x1b[36m+---------------------------+\x1b[0m   \x1b[31m+---------------------------------+\x1b[0m");
    println!("\x1b[35m| Incoming                 |\x1b[0m   \x1b[36m| Outgoing                  |\x1b[0m   \x1b[31m| Diversified                     |\x1b[0m");
    println!("\x1b[35m| viewing key              |\x1b[0m   \x1b[36m| viewing key               |\x1b[0m   \x1b[31m| payment addresses               |\x1b[0m");
    println!("\x1b[35m| (dk: diversifier key,    |\x1b[0m   \x1b[36m| (outgoing viewing key)    |\x1b[0m   \x1b[31m| (d: diversifier,                |\x1b[0m");
    println!("\x1b[35m|  ivk: incoming           |\x1b[0m   \x1b[36m| ovk                       |\x1b[0m   \x1b[31m|  pk_d: diversified transmission |\x1b[0m");
    println!("\x1b[35m|  viewing key)            |\x1b[0m   \x1b[36m|                           |\x1b[0m   \x1b[31m|  key - public)                  |\x1b[0m");
    println!("\x1b[35m| (dk, ivk)                |\x1b[0m   \x1b[36m+---------------------------+\x1b[0m   \x1b[31m| addr_d = (d, pk_d)              |\x1b[0m");
    println!("\x1b[35m+--------------------------+\x1b[0m                                         \x1b[31m+---------------------------------+\x1b[0m");



    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <sk_hex or mnemonic>", args[0]);
        process::exit(1);
    }

    // Determine if the input is a hex string (32 bytes) or a mnemonic
    let input = &args[1];
    let sk: SpendingKey = if input.contains(' ') {
        // Treat as mnemonic
        let mnemonic = match Mnemonic::parse(input) {
            Ok(m) => m,
            Err(e) => {
                eprintln!("Invalid mnemonic: {}", e);
                process::exit(1);
            }
        };
        println!("\n\nMnemonic:  {}", input);
        print!("\n                               ↓\n\n");
        let seed = mnemonic.to_seed("");
        const COIN_TYPE: u32 = 133; // Zcash mainnet
        let account = AccountId::try_from(0u32).expect("Valid account ID");
        SpendingKey::from_zip32_seed(&seed, COIN_TYPE, account)
            .expect("Failed to derive spending key from seed")
    } else {
        // Treat as sk_hex
        let sk_bytes = match decode(input) {
            Ok(bytes) => bytes,
            Err(e) => {
                eprintln!("Invalid hex: {}", e);
                process::exit(1);
            }
        };
        if sk_bytes.len() != 32 {
            eprintln!("Spending key must be 32 bytes");
            process::exit(1);
        }
        let mut sk_array = [0u8; 32];
        sk_array.copy_from_slice(&sk_bytes);
        let sk_opt: CtOption<SpendingKey> = SpendingKey::from_bytes(sk_array);
        if bool::from(sk_opt.is_some()) {
            sk_opt.unwrap()
        } else {
            eprintln!("Invalid spending key");
            process::exit(1);
        }
    };

    // Print the SK in hex
    let sk_bytes = sk.to_bytes();
    println!("SK   :    {}", hex::encode(sk_bytes));
    print!("\n                               ↓\n\n");

    // Derive the ASK from the SK and print it in hex

    // Manually derive ASK bytes for printing (since no to_bytes() on SpendAuthorizingKey)
    let mut params = Params::new();
    params.hash_length(64);
    params.key(sk_bytes);
    let prf = params.hash(&[6]);
    let prf_bytes: [u8; 64] = prf.as_bytes().try_into().expect("64 bytes");
    let ask_scalar = pasta_curves::pallas::Scalar::from_uniform_bytes(&prf_bytes);
    let ask_bytes = ask_scalar.to_repr();
    println!("ASK  :    {}", hex::encode(ask_bytes.as_slice()));

    // Print the ASK using the SpendAuthorizingKey's inherent debug formatting this doesnt work in orchard 0.11
    //let ask : SpendAuthorizingKey = (&sk).into();
    //println!("ASK  :    {:?}", ask); 
    //print!("\n                               ↓\n\n");


    // Derive the Spend Validating Key (AK) from the SK and print it in hex
    //let ak: SpendValidatingKey = (&ask).into();
    //println!("AK  :    {}", hex::encode(ak.to_bytes()));
    print!("\n                               ↓\n\n");


    // Derive the FVK from the SK and print it in hex
    let fvk: FullViewingKey = (&sk).into();

    //FKV is a 96-byte array in the order ak (0..32), nk (32..64), rivk (64..96)
    let fvk_bytes = fvk.to_bytes();
    println!("FVK  :    {}", hex::encode(fvk_bytes));
    print!("\n                               ↓\n\n");

    let nk_bytes = &fvk_bytes[32..64];
    let rivk_bytes = &fvk_bytes[64..96];
    let ak_bytes = &fvk_bytes[0..32];

    println!("                      [AK, NK, RIVK] (extracted from FVK):\n");
    println!("AK   : {}", hex::encode(ak_bytes));
    println!("NK   : {}", hex::encode(nk_bytes));
    println!("RIVK : {}", hex::encode(rivk_bytes));
    print!("\n                               ↓                                   ↓\n\n");

    // Create IVKs for both external and internal scopes and display them in hex
    let ivk: IncomingViewingKey = fvk.to_ivk(Scope::External);
    let ivk_internal = fvk.to_ivk(Scope::Internal);

    // Create OVKs for both external and internal scopes and display them in hex
    let ovk = fvk.to_ovk(Scope::External);
    let ovk_bytes = ovk.as_ref();

    let ovk_internal = fvk.to_ovk(Scope::Internal);
    let ovk_internal_bytes = ovk_internal.as_ref();

    println!("                              IVK                                 OVK");
    println!("                          ↙          ↘                         ↙        ↘");
    println!("                      IVK_e            IVK_i               OVK_e           OVK_i\n");

    println!("IVK_e:    {}", hex::encode(ivk.to_bytes()));
    println!("IVK_i:    {}\n", hex::encode(ivk_internal.to_bytes()));
    println!("OVK_e:    {}", hex::encode(ovk_bytes));
    println!("OVK_i:    {}\n", hex::encode(ovk_internal_bytes));
    print!("\n                               ↓\n\n");

    // Display human-readable encodings of the IVK and FVK using the MainNetwork parameters

    println!("NOTE: There is no Bech32[m] encoding defined for any individual Orchard incoming viewing key / Orchard full viewing key; instead use a unified
incoming viewing key / unified full viewing key as defined in [ZIP-316].\n");


    let uivk = UnifiedIncomingViewingKey::new(None, None, Some(ivk));
    let uivk_internal = UnifiedIncomingViewingKey::new(None, None, Some(ivk_internal));
    let uivk_str = uivk.encode(&zcash_protocol::consensus::MainNetwork);
    let uivk_internal_str = uivk_internal.encode(&zcash_protocol::consensus::MainNetwork);

    println!("UIVK_i_encoded : {}", uivk_internal_str);
    println!("UIVK_e_encoded : {}", uivk_str);


    let ufvk = UnifiedFullViewingKey::new(None, None, Some(fvk.clone()))
        .expect("Valid UFVK");
    let ufvk_str = ufvk.encode(&zcash_protocol::consensus::MainNetwork);
    println!("UFVK_encoded   : {}", ufvk_str);
    print!("\n                               ↓\n\n");
    
    let ua_raw = Some(fvk.address_at(0u32, Scope::External))
        .expect("Valid address").to_raw_address_bytes();

    println!("\n\nPayment address at diversifier index 0 (raw bytes): {}", hex::encode(ua_raw));
    
    let receiver = Receiver::Orchard(ua_raw);

    let myaddress =UnifiedAddress::try_from_items(vec![receiver])
        .expect("Orchard receivers are valid items for a UA");

    println!("Payment address at diversifier index 0 \"encoded\" (Unified Address): {}", myaddress.encode(&zcash_primitives::consensus::NetworkType::Main));
}