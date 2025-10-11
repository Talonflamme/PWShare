use proc_macro::TokenStream;
use quote::quote;
use syn::parse::{Parse, ParseStream};
use syn::{Ident, LitInt, Token, parse_macro_input};

struct CipherTestInput {
    array_ident: Ident,
    array_len: LitInt,
}

impl Parse for CipherTestInput {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let array_ident = input.parse::<Ident>()?;
        input.parse::<Token![,]>()?;
        let array_len = input.parse::<LitInt>()?;
        Ok(CipherTestInput {
            array_ident,
            array_len,
        })
    }
}

pub fn generate_cipher_tests(input: TokenStream) -> TokenStream {
    let CipherTestInput {
        array_ident,
        array_len,
    } = parse_macro_input!(input as CipherTestInput);
    let len: usize = array_len
        .base10_parse()
        .expect("Array length must be a valid integer");

    // Generate test functions
    let test_fns = (0..len).map(|i| {
        let test_name = Ident::new(&format!("test_cipher_{}", i), array_ident.span());
        let index = syn::Index::from(i);
        quote! {
            #[test]
            fn #test_name() {
                println!("Testing cipher: {:?}", #array_ident[#index]);
                test_cipher_suite(#array_ident[#index], #index);
            }
        }
    });

    let expanded = quote! {
        #[test]
        fn test_all_ciphers_are_tested() {
            assert_eq!(#array_ident .len(), #array_len, "Second argument of `generate_cipher_tests` does not match the array length. I.e: Not all ciphers are tested.");
        }

        #(#test_fns)*
    };

    expanded.into()
}
