mod cipher_suite_tests;
mod f128;
mod from_repr;
mod into_repr;
mod readable_from_stream;
mod writable_to_sink;

use crate::f128::F128;
use crate::from_repr::impl_from_repr;
use crate::into_repr::impl_into_repr;
use crate::writable_to_sink::impl_writable_to_sink;
use proc_macro::TokenStream;
use proc_macro2::Span;
use quote::quote;
use readable_from_stream::impl_readable_from_stream_trait;
use syn::{DeriveInput, Ident, LitInt};

fn get_repr_type(ast: &DeriveInput) -> Option<Ident> {
    for attr in &ast.attrs {
        if !attr.path().is_ident("repr") {
            continue;
        }

        let mut ty: Option<Ident> = None;

        attr.parse_nested_meta(|meta| {
            match meta.path.get_ident().unwrap().to_string().as_str() {
                "u8" | "u16" | "u32" | "u64" | "u128" => {
                    ty = meta.path.get_ident().cloned();
                }
                _ => {}
            }

            Ok(())
        })
        .unwrap();

        if ty.is_some() {
            return ty;
        }
    }

    None
}

#[proc_macro_derive(ReadableFromStream)]
pub fn readable_from_stream_macro(item: TokenStream) -> TokenStream {
    let ast: DeriveInput = syn::parse(item).unwrap();
    impl_readable_from_stream_trait(ast)
}

#[proc_macro_derive(WritableToSink)]
pub fn writable_to_sink_macro(item: TokenStream) -> TokenStream {
    let ast = syn::parse(item).unwrap();
    impl_writable_to_sink(ast).into()
}

#[proc_macro_derive(FromRepr)]
pub fn from_repr(item: TokenStream) -> TokenStream {
    let ast = syn::parse(item).unwrap();
    impl_from_repr(ast)
}

#[proc_macro_derive(IntoRepr)]
pub fn into_repr(item: TokenStream) -> TokenStream {
    let ast = syn::parse(item).unwrap();
    impl_into_repr(ast)
}

#[proc_macro]
pub fn generate_k_md5(_: TokenStream) -> TokenStream {
    let md5: Vec<_> = (0..64)
        .map(|i| (f64::sin(i as f64 + 1.0).abs() * (1u64 << 32) as f64) as u32)
        .map(|n| LitInt::new(format!("0x{:x}u32", n).as_str(), Span::call_site()))
        .collect();
    quote! {
        [#(#md5),*]
    }
    .into()
}

fn generate_primes(n: usize) -> Box<dyn Iterator<Item = u32>> {
    Box::new(
        (2..)
            .filter(|x| {
                // is prime?
                if *x <= 3 {
                    return true;
                }

                for i in 2..=((*x as f32).sqrt().ceil() as u32) {
                    if x % i == 0 {
                        // composite
                        return false;
                    }
                }
                true
            })
            .take(n),
    )
}

#[proc_macro]
pub fn generate_k_sha256(_: TokenStream) -> TokenStream {
    // first 64 primes
    let primes = generate_primes(64);

    let fractional_parts = primes.map(|prime| {
        let cbrt = (prime as f64).cbrt();
        let frac = (cbrt.fract() + 1.0).to_bits();

        // by only taking the `.fract()` and then adding 1, the mantissa/fractional/significand
        // becomes exactly the part we need

        // mantissa is 52 bits, we want 32 bits of precision -> shift by 20
        ((frac) >> ((f64::MANTISSA_DIGITS - 1) - 32)) as u32
    });

    let literals = fractional_parts
        .map(|frac| LitInt::new(format!("0x{:x}u32", frac).as_str(), Span::call_site()));

    quote! {
        [#(#literals),*]
    }
    .into()
}

#[proc_macro]
pub fn generate_k_sha512(_: TokenStream) -> TokenStream {
    let primes = generate_primes(80);

    let fractional_parts = primes.map(|prime| {
        let cbrt = F128::from(prime as f64).cbrt();

        let frac = cbrt.set_integer_part_to_one().mantissa.without_leading_1();
        let res = (frac >> (112 - 64)) as u64;

        res
    });

    let literals = fractional_parts
        .map(|frac| LitInt::new(format!("0x{:x}u64", frac).as_str(), Span::call_site()));

    quote! {
        [#(#literals),*]
    }
    .into()
}

#[proc_macro]
pub fn generate_cipher_suite_tests(input: TokenStream) -> TokenStream {
    cipher_suite_tests::generate_cipher_tests(input)
}
