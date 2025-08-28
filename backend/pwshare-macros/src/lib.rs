mod readable_from_stream;
mod from_repr;
mod into_repr;

use crate::from_repr::impl_from_repr;
use crate::into_repr::impl_into_repr;
use proc_macro::TokenStream;
use readable_from_stream::impl_readable_from_stream_trait;
use syn::{DeriveInput, Ident};

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
