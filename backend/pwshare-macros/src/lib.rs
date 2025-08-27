use proc_macro::{Span, TokenStream};
use quote::quote;
use syn::{Data, DeriveInput, Expr, Fields, Ident, Lit, LitInt, LitStr};

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

fn impl_readable_from_stream_trait(ast: DeriveInput) -> TokenStream {
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
                    _ => Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("Expected any valid value for {}, got: {}", #lit_name, value)
                    )),
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

    quote! {
        impl crate::tls::ReadableFromStream for #name {
            fn read(stream: &mut impl Iterator<Item=u8>) -> std::io::Result<#name> {
                #body
            }
        }
    }
    .into()
}

fn impl_from_repr(ast: DeriveInput) -> TokenStream {
    let Data::Enum(en) = &ast.data else {
        return quote! { compile_error("Can only use FromRepr on enums"); }.into();
    };

    let name = &ast.ident;

    let repr = get_repr_type(&ast);

    if repr.is_none() {
        return quote! { compile_error("Need repr definition to have FromRepr"); }.into();
    }

    let repr = repr.unwrap();
    let mut last_value: u128 = 0;
    let mut variants = Vec::new();

    for variant in &en.variants {
        if !variant.fields.is_empty() {
            return quote! { compile_error("FromRepr requires all variants to not have fields"); }
                .into();
        }

        let value = if let Some((_, Expr::Lit(disc))) = &variant.discriminant {
            let Lit::Int(disc) = &disc.lit else {
                return quote! { compile_error("Unexpected literal as discriminant"); }.into();
            };

            disc.base10_parse::<u128>().unwrap().into()
        } else {
            last_value
        };

        let variant_name = &variant.ident;

        let value_lit = LitInt::new(&value.to_string(), Span::call_site().into()); // need this, so that quote does not add "_u128" to the number

        variants.push(quote! { #value_lit => Ok(Self::#variant_name) });
        last_value = value + 1;
    }

    let name_str = name.to_string();

    quote! {
        impl TryFrom<#repr> for #name {
            type Error = String;

            fn try_from(value: #repr) -> Result<Self, Self::Error> {
                match value {
                    #(#variants),*,
                    _ => Err(format!("Cannot parse {} to {}", value, #name_str))
                }
            }
        }
    }
    .into()
}

fn impl_into_repr(ast: DeriveInput) -> TokenStream {
    let Data::Enum(en) = &ast.data else {
        return quote! { compile_error("Can only use FromRepr on enums"); }.into();
    };

    let name = &ast.ident;
    let repr = get_repr_type(&ast);

    if repr.is_none() {
        return quote! { compile_error("Need repr definition to derive IntoRepr"); }.into();
    }

    let repr = repr.unwrap();
    let mut last_value: u128 = 0;
    let mut variants = Vec::new();

    for variant in &en.variants {
        let amount_fields = variant.fields.len();

        let value = if let Some((_, Expr::Lit(disc))) = &variant.discriminant {
            let Lit::Int(disc) = &disc.lit else {
                return quote! { compile_error("Unexpected literal as discriminant"); }.into();
            };

            disc.base10_parse::<u128>().unwrap().into()
        } else {
            last_value
        };

        let variant_name = &variant.ident;

        let fields = if amount_fields > 0 {
            let underscores = std::iter::repeat(quote! { _ })
                .take(amount_fields);
            quote! { ( #(#underscores),* ) }
        } else {
            quote!{}
        };

        let value_lit = LitInt::new(&value.to_string(), Span::call_site().into()); // need this, so that quote does not add "_u128" to the number

        variants.push(quote! { #name::#variant_name #fields => #value_lit });
        last_value = value + 1;
    }

    quote! {
        impl Into<#repr> for & #name {
            fn into(self) -> #repr {
                match self {
                    #(#variants),*
                }
            }
        }
    }
    .into()
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
