use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, Data, DeriveInput, Fields};

/// Derive macro for IntoTypedValue trait
///
/// This macro generates a direct implementation of IntoTypedValue for structs.
///
/// Example usage:
/// ```ignore
/// use pod_derive::IntoTypedValue;
///
/// #[derive(IntoTypedValue)]
/// struct Person {
///     name: String,
///     age: i64,
///     active: bool,
/// }
/// ```
#[proc_macro_derive(IntoTypedValue)]
pub fn derive_into_typed_value(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    let name = &input.ident;
    let generics = &input.generics;
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    let into_typed_value_impl = match &input.data {
        Data::Struct(data_struct) => match &data_struct.fields {
            Fields::Named(fields) => {
                let field_conversions = fields.named.iter().map(|field| {
                    let field_name = &field.ident;
                    let field_name_str = field_name.as_ref().unwrap().to_string();
                    let field_type = &field.ty;

                    // Check if the field type is a Vec
                    if let syn::Type::Path(type_path) = field_type {
                        if let Some(segment) = type_path.path.segments.last() {
                            if segment.ident == "Vec" {
                                // Custom logic for Vec fields
                                return quote! {
                                    let inner_values = self.#field_name.iter().cloned().map(|v| {let t: TypedValue = v.into(); t.into() }).collect::<Vec::<pod2::middleware::Value>>();
                                    let pod_key = Key::from(#field_name_str.to_string());
                                    let array = pod2::middleware::containers::Array::new(5, inner_values).unwrap();
                                    let typed_value: TypedValue = array.into();
                                    let value: pod2::middleware::Value = typed_value.into();
                                    dict_entries.insert(pod_key, value);
                                };
                            }
                            if segment.ident == "HashSet" {
                                // Custom logic for HashSet fields
                                return quote! {
                                    let inner_values = self.#field_name.iter().cloned().map(|v| {let t: TypedValue = v.into(); t.into() }).collect::<HashSet::<pod2::middleware::Value>>();
                                    let pod_key = Key::from(#field_name_str.to_string());
                                    let set = pod2::middleware::containers::Set::new(5, inner_values).unwrap();
                                    let typed_value: TypedValue = set.into();
                                    let value: pod2::middleware::Value = typed_value.into();
                                    dict_entries.insert(pod_key, value);
                                };
                            }
                        }
                    }

                    // Default conversion for non-Vec fields
                    quote! {
                        let pod_key = Key::from(#field_name_str.to_string());
                        let typed_value: TypedValue = self.#field_name.into();
                        let value: pod2::middleware::Value = typed_value.into();
                        dict_entries.insert(pod_key, value);
                    }
                });

                quote! {
                    fn into(self) -> TypedValue {
                        use std::collections::HashMap;
                        use pod2::middleware::{
                            Key, TypedValue,
                            containers::Dictionary,
                        };

                        let mut dict_entries: HashMap<Key, pod2::middleware::Value> = HashMap::new();
                        #(#field_conversions)*

                        let pod_dict = Dictionary::new(5, dict_entries)
                            .expect("Dictionary creation should not fail with valid entries");

                        TypedValue::Dictionary(pod_dict)
                    }
                }
            }
            Fields::Unnamed(_) => {
                return syn::Error::new_spanned(
                    &input.ident,
                    "IntoTypedValue derive macro only supports named fields",
                )
                .to_compile_error()
                .into();
            }
            Fields::Unit => {
                quote! {
                    fn into(self) -> TypedValue {
                        use std::collections::HashMap;
                        use pod2::middleware::{
                            TypedValue,
                            containers::Dictionary,
                        };

                        let dict_entries = HashMap::new();
                        let pod_dict = Dictionary::new(5, dict_entries)
                            .expect("Empty dictionary creation should not fail");

                        TypedValue::Dictionary(pod_dict)
                    }
                }
            }
        },
        Data::Enum(_) => {
            return syn::Error::new_spanned(
                &input.ident,
                "IntoTypedValue derive macro does not support enums yet",
            )
            .to_compile_error()
            .into();
        }
        Data::Union(_) => {
            return syn::Error::new_spanned(
                &input.ident,
                "IntoTypedValue derive macro does not support unions",
            )
            .to_compile_error()
            .into();
        }
    };

    let expanded = quote! {
        impl #impl_generics Into<TypedValue> for #name #ty_generics #where_clause {
            #into_typed_value_impl
        }
    };

    TokenStream::from(expanded)
}
