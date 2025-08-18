use proc_macro::TokenStream;
use quote::quote;
use syn::{Data, DeriveInput, Fields};

fn impl_readable_from_stream_trait(ast: DeriveInput) -> TokenStream {
    let name = ast.ident;

    let body = match ast.data {
        Data::Struct(data_struct) => {
            match data_struct.fields {
                Fields::Named(fields) => {
                    let calls = fields.named.iter().map(|f| {
                        let ident = f.ident.as_ref().unwrap();
                        let ty = &f.ty;
                        
                        quote! { #ident: <#ty as ReadableFromStream>::read(stream)? }
                    });
                    quote! { #( #calls ),* }
                }
                Fields::Unnamed(fields) => {
                    let calls = fields.unnamed.iter().enumerate().map(|(i, f)| {
                        let ty = &f.ty;
                        let idx = syn::Index::from(i);
                        quote! { #idx: <#ty as ReadableFromStream>::read(stream)? }
                    });
                    quote! { #( #calls ),* }
                }
                Fields::Unit => {
                    quote! {}
                }
            }
        }
        _ => {
            quote! {
                compile_error!("ReadableFromStream only works on structs");
            }
        }
    };

    quote! {
        impl ReadableFromStream for #name {
            fn read(stream: &mut impl Iterator<Item=u8>) -> std::io::Result<#name> {
                Ok(#name {
                    #body
                })
            }
        }
    }.into()
}

#[proc_macro_derive(ReadableFromStream)]
pub fn readable_from_stream_macro(item: TokenStream) -> TokenStream {
    let ast: DeriveInput = syn::parse(item).unwrap();

    impl_readable_from_stream_trait(ast)
}
