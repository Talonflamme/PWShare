use proc_macro::{Span, TokenStream};
use quote::quote;
use syn::{Data, DeriveInput, Expr, Lit, LitInt};
use crate::get_repr_type;

pub fn impl_into_repr(ast: DeriveInput) -> TokenStream {
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
