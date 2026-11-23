// Copyright (c) 2019-2026 Provable Inc.
// This file is part of the snarkVM library.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:

// http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#![warn(clippy::cast_possible_truncation)]

extern crate proc_macro;

use proc_macro::{Group, Ident, TokenStream, TokenTree};

fn recursively_replace_self(stream: TokenStream, replacement: &str) -> TokenStream {
    stream
        .into_iter()
        .map(|item| match item {
            TokenTree::Ident(ident) => {
                if ident.to_string() == "self" {
                    TokenTree::Ident(Ident::new(replacement, ident.span()))
                } else {
                    TokenTree::Ident(ident)
                }
            }
            TokenTree::Group(group) => {
                TokenTree::Group(Group::new(group.delimiter(), recursively_replace_self(group.stream(), replacement)))
            }
            i => i,
        })
        .collect()
}

#[proc_macro]
pub fn rename_selfs(stream: TokenStream) -> TokenStream {
    recursively_replace_self(stream, "_self")
}
