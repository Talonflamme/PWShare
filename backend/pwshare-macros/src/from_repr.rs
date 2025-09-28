use proc_macro::{Span, TokenStream};
use quote::quote;
use syn::{Data, DeriveInput, Expr, Lit, LitInt};
use crate::get_repr_type;

pub fn impl_from_repr(ast: DeriveInput) -> TokenStream {
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

            fn try_from(value: #repr) -> std::result::Result<Self, Self::Error> {
                match value {
                    #(#variants),*,
                    _ => Err(format!("Cannot parse {} to {}", value, #name_str))
                }
            }
        }
    }
        .into()
}
