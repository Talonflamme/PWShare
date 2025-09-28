use proc_macro::TokenStream;
use quote::{quote, ToTokens};
use syn::{Data, DeriveInput, Fields, LitStr};
use crate::get_repr_type;

pub fn impl_readable_from_stream_trait(ast: DeriveInput) -> TokenStream {
    let name = &ast.ident;

    let body = match &ast.data {
        Data::Struct(data_struct) => match &data_struct.fields {
            Fields::Named(fields) => {
                let calls = fields.named.iter().map(|f| {
                    let ident = f.ident.as_ref().unwrap();
                    let ty = &f.ty;

                    quote! { #ident: <#ty as crate::tls::ReadableFromStream>::read(stream)? }
                });
                quote! { Ok(Self { #( #calls ),* }) }
            }
            Fields::Unnamed(fields) => {
                let calls = fields.unnamed.iter().enumerate().map(|(i, f)| {
                    let ty = &f.ty;
                    let idx = syn::Index::from(i);
                    quote! { #idx: <#ty as crate::tls::ReadableFromStream>::read(stream)? }
                });
                quote! { Ok(Self { #( #calls ),* }) }
            }
            Fields::Unit => {
                quote! { Ok(Self) }
            }
        },
        Data::Enum(data_enum) => {
            let repr = get_repr_type(&ast);

            if repr.is_none() {
                return quote! { compile_error!("ReadableFromStream requires repr attribute with any unsigned integer on enum."); }.into();
            }

            let repr = repr.unwrap();
            let mut cases = Vec::with_capacity(data_enum.variants.len());

            for variant in data_enum.variants.iter() {
                let variant_name = &variant.ident;
                let mut fields = Vec::with_capacity(variant.fields.len() + 2);

                let mut is_named_fields = false;

                for field in &variant.fields {
                    let ty = &field.ty;

                    if let Some(ident) = field.ident.as_ref() {
                        // named struct
                        is_named_fields = true;
                        fields.push(quote! { #ident: <#ty as crate::tls::ReadableFromStream>::read(stream)? });
                    } else {
                        fields.push(
                            quote! { <#ty as crate::tls::ReadableFromStream>::read(stream)? },
                        );
                    }
                }

                let fields = if is_named_fields {
                    quote! { { #(#fields),* } }
                } else if fields.len() > 0 {
                    quote! { ( #(#fields),* ) }
                } else {
                    quote! {}
                };

                if let Some((_, value)) = &variant.discriminant {
                    cases.push(quote! { #value => Ok(#name::#variant_name #fields ) });
                } else {
                    return quote! { compile_error!("ReadableFromStream requires all variants to have a discriminant"); }.into();
                }
            }

            let lit_name = LitStr::new(name.to_string().as_str(), name.span());

            quote! {
                let value: #repr = crate::tls::ReadableFromStream::read(stream)?;
                match value {
                    #( #cases ),*,
                    _ => Err(crate::tls::record::alert::Alert::decode_error()),
                }
            }
        }
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
        impl #generics crate::tls::ReadableFromStream for #name #generics #generics_where {
            fn read(stream: &mut impl Iterator<Item=u8>) -> crate::tls::record::alert::Result<Self> {
                #body
            }
        }
    }
        .into()
}