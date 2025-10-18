use crate::*;
use proc_macro2::TokenStream;
use quote::{ToTokens, quote};
use syn::{Data, DataEnum, DataStruct, DeriveInput, Fields};

fn impl_writable_to_sink_struct(
    data_struct: &DataStruct,
    fallback_attr: Option<&Attribute>,
) -> TokenStream {
    if fallback_attr.is_some() {
        return quote! { compile_error!("[fallback] is only usable for enums."); };
    }

    match &data_struct.fields {
        Fields::Named(fields) => {
            let calls = fields.named.iter().map(|f| {
                let ident = f.ident.as_ref().unwrap();
                quote! { crate::tls::WritableToSink::write(&self.#ident , buffer, suite)?; }
            });
            quote! { #(#calls)* Ok(()) }
        }
        Fields::Unnamed(fields) => {
            let calls = fields.unnamed.iter().enumerate().map(|(i, _)| {
                let idx = syn::Index::from(i);
                quote! { crate::tls::WritableToSink::write(&self.#idx , buffer, suite)?; }
            });
            quote! { #(#calls)* Ok(()) }
        }
        Fields::Unit => {
            quote! { Ok(()) }
        }
    }
}

fn impl_writable_to_sink_enum(
    data_enum: &DataEnum,
    ast: &DeriveInput,
    fallback_attr: Option<&Attribute>,
) -> TokenStream {
    let name = &ast.ident;
    let repr = get_repr_type(ast);
    let fallback = get_fallback_name(fallback_attr);

    if repr.is_none() {
        return quote! { compile_error!("WritableToSink requires repr attribute with any unsigned integer on enum."); }.into();
    }

    let repr = repr.unwrap();
    let mut cases = Vec::with_capacity(data_enum.variants.len());

    for variant in &data_enum.variants {
        let mut field_definition = Vec::with_capacity(variant.fields.len());
        let mut field_body = Vec::with_capacity(variant.fields.len());
        let variant_name = &variant.ident;
        let mut is_named_fields = false;

        for (i, field) in variant.fields.iter().enumerate() {
            let field_i: TokenStream = if let Some(id) = &field.ident {
                is_named_fields = true;
                quote! { #id }
            } else {
                format!("field{}", i).parse().unwrap()
            };

            field_definition.push(field_i.clone());

            field_body.push(quote! { crate::tls::WritableToSink::write(#field_i, buffer, suite)? });
        }

        let fields = if field_definition.is_empty() {
            quote! {}
        } else if !is_named_fields {
            quote! { ( #(#field_definition),* ) }
        } else {
            quote! { { #(#field_definition),* } }
        };

        if let Some(fb) = fallback.as_ref()
            && fb == variant_name
        {
            cases.push(quote! { #name::#variant_name #fields => {
                return Err(crate::tls::record::alert::Alert::internal_error("Cannot write: "));
            } })
        } else if let Some((_, disc)) = &variant.discriminant {
            cases.push(quote! { #name::#variant_name #fields => {
                <#repr as crate::tls::WritableToSink>::write(&#disc, buffer, suite)?;
                #(#field_body);*
            } });
        } else {
            return quote! { compile_error("WritableToSink requires all enum variants to have a discriminant"); };
        }
    }

    quote! {
        match self {
            #(#cases)*
        }
        Ok(())
    }
}

pub fn impl_writable_to_sink(ast: DeriveInput) -> TokenStream {
    let name = &ast.ident;
    let fallback_attr = get_attr(&ast, "fallback");

    let body = match &ast.data {
        Data::Struct(data_struct) => impl_writable_to_sink_struct(data_struct, fallback_attr),
        Data::Enum(data_enum) => impl_writable_to_sink_enum(data_enum, &ast, fallback_attr),
        _ => {
            return quote! {
                compile_error!("ReadableFromStream only works on structs");
            }
            .into();
        }
    };

    let generics = ast.generics.to_token_stream();
    let generics_where = ast.generics.where_clause;

    quote! {
        impl #generics crate::tls::WritableToSink for #name #generics #generics_where {
            fn write(&self, buffer: &mut impl crate::tls::Sink<u8>, suite: Option<&crate::tls::record::ciphers::cipher_suite::CipherConfig>) -> crate::tls::record::alert::Result<()> {
                #body
            }
        }
    }
    .into()
}
