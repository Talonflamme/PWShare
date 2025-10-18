use crate::*;
use proc_macro::TokenStream;
use quote::{ToTokens, quote};
use syn::{Data, DataEnum, DataStruct, DeriveInput, Fields};

fn readable_from_stream_for_struct(
    data_struct: &DataStruct,
    fallback: Option<&Attribute>,
) -> proc_macro2::TokenStream {
    if fallback.is_some() {
        return quote! { compile_error!("[fallback] is only usable for enums."); };
    }

    match &data_struct.fields {
        Fields::Named(fields) => {
            let calls = fields.named.iter().map(|f| {
                let ident = f.ident.as_ref().unwrap();
                let ty = &f.ty;

                quote! { #ident: <#ty as crate::tls::ReadableFromStream>::read(stream, suite)? }
            });
            quote! { Ok(Self { #( #calls ),* }) }
        }
        Fields::Unnamed(fields) => {
            let calls = fields.unnamed.iter().enumerate().map(|(i, _)| {
                let idx = syn::Index::from(i);
                quote! { #idx: crate::tls::ReadableFromStream::read(stream, suite)? }
            });
            quote! { Ok(Self { #( #calls ),* }) }
        }
        Fields::Unit => {
            quote! { Ok(Self) }
        }
    }
}

fn readable_from_stream_for_enum(
    ast: &DeriveInput,
    name: &Ident,
    data_enum: &DataEnum,
    fallback: Option<&Attribute>,
) -> proc_macro2::TokenStream {
    let fallback = get_fallback_name(fallback);

    let repr = get_repr_type(ast);

    if repr.is_none() {
        return quote! { compile_error!("ReadableFromStream requires repr attribute with any unsigned integer on enum."); }.into();
    }

    let repr = repr.unwrap();
    let mut cases = Vec::with_capacity(data_enum.variants.len());
    let mut fallback_case: Option<proc_macro2::TokenStream> = None;

    for variant in data_enum.variants.iter() {
        let variant_name = &variant.ident;
        let mut fields = Vec::with_capacity(variant.fields.len() + 2);

        let mut is_named_fields = false;

        for field in &variant.fields {
            if let Some(ident) = field.ident.as_ref() {
                // named struct
                is_named_fields = true;
                fields
                    .push(quote! { #ident: crate::tls::ReadableFromStream::read(stream, suite)? });
            } else {
                fields.push(quote! { crate::tls::ReadableFromStream::read(stream, suite)? });
            }
        }

        let fields = if is_named_fields {
            quote! { { #(#fields),* } }
        } else if fields.len() > 0 {
            quote! { ( #(#fields),* ) }
        } else {
            quote! {}
        };

        if let Some(fb) = fallback.as_ref()
            && fb == variant_name
        {
            fallback_case = Some(quote! { Ok(#name::#variant_name #fields) });
        } else if let Some((_, value)) = &variant.discriminant {
            let case = quote! { Ok(#name::#variant_name #fields ) };
            cases.push(quote! { #value => #case });
        } else {
            return quote! { compile_error!("ReadableFromStream requires all variants to have a discriminant"); }.into();
        }
    }

    if fallback.is_some() && fallback_case.is_none() {
        return quote! { compile_error!("[fallback] with unknown variant"); };
    }

    let fallback = if let Some(fbc) = fallback_case {
        fbc
    } else {
        quote! { Err(crate::tls::record::alert::Alert::decode_error()) }
    };

    quote! {
         let value: #repr = crate::tls::ReadableFromStream::read(stream, suite)?;
         match value {
             #( #cases ),*,
             _ => #fallback,
        }
    }
}

pub fn impl_readable_from_stream_trait(ast: DeriveInput) -> TokenStream {
    let name = &ast.ident;
    let fallback_attr = get_attr(&ast, "fallback");

    let body = match &ast.data {
        Data::Struct(ds) => readable_from_stream_for_struct(ds, fallback_attr),
        Data::Enum(de) => readable_from_stream_for_enum(&ast, name, de, fallback_attr),
        _ => {
            return quote! {compile_error!("ReadableFromStream only works on structs");}.into();
        }
    };

    let generics = ast.generics.to_token_stream();
    let generics_where = ast.generics.where_clause;

    quote! {
        impl #generics crate::tls::ReadableFromStream for #name #generics #generics_where {
            fn read(stream: &mut impl Iterator<Item=u8>, suite: Option<&crate::tls::record::ciphers::cipher_suite::CipherConfig>) -> crate::tls::record::alert::Result<Self> {
                #body
            }
        }
    }.into()
}
