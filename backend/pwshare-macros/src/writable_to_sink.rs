use crate::get_repr_type;
use proc_macro2::TokenStream;
use quote::{quote, ToTokens};
use syn::{Data, DataEnum, DataStruct, DeriveInput, Fields};

fn impl_writable_to_sink_struct(data_struct: &DataStruct) -> TokenStream {
    match &data_struct.fields {
        Fields::Named(fields) => {
            let calls = fields.named.iter().map(|f| {
                let ident = f.ident.as_ref().unwrap();
                let ty = &f.ty;

                quote! { <#ty as crate::tls::WritableToSink>::write(&self.#ident , buffer)?; }
            });
            quote! { #(#calls)* Ok(()) }
        }
        Fields::Unnamed(fields) => {
            let calls = fields.unnamed.iter().enumerate().map(|(i, f)| {
                let ty = &f.ty;
                let idx = syn::Index::from(i);
                quote! { <#ty as crate::tls::WritableToSink>::write(&self.#idx , buffer)?; }
            });
            quote! { #(#calls)* Ok(()) }
        }
        Fields::Unit => {
            quote! { Ok(()) }
        }
    }
}

fn impl_writable_to_sink_enum(data_enum: &DataEnum, ast: &DeriveInput) -> TokenStream {
    let name = &ast.ident;
    let repr = get_repr_type(ast);

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

        let Some((_, disc)) = &variant.discriminant else {
            return quote! { compile_error("WritableToSink requires all enum variants to have a discriminant"); };
        };

        for (i, field) in variant.fields.iter().enumerate() {
            let field_i: TokenStream = if let Some(id) = &field.ident {
                is_named_fields = true;
                quote! { #id }
            } else {
                format!("field{}", i).parse().unwrap()
            };

            field_definition.push(field_i.clone());

            let ty = &field.ty;
            field_body
                .push(quote! { <#ty as crate::tls::WritableToSink>::write(#field_i, buffer)? });
        }

        let fields = if field_definition.is_empty() {
            quote! {}
        } else if !is_named_fields {
            quote! { ( #(#field_definition),* ) }
        } else {
            quote! { { #(#field_definition),* } }
        };

        cases.push(quote! { #name::#variant_name #fields => {
            <#repr as crate::tls::WritableToSink>::write(&#disc, buffer)?;
            #(#field_body);*
        } });
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

    let body = match &ast.data {
        Data::Struct(data_struct) => impl_writable_to_sink_struct(data_struct),
        Data::Enum(data_enum) => impl_writable_to_sink_enum(data_enum, &ast),
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
            fn write(&self, buffer: &mut impl crate::tls::Sink<u8>) -> std::io::Result<()> {
                #body
            }
        }
    }
    .into()
}
