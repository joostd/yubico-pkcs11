/*
 * Copyright 2026 Yubico AB
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#![allow(non_snake_case)]
#![allow(unused_variables)]

extern crate pkcs11_common;
extern crate yubikit;

mod backend;
mod create_object;
mod decrypt;
mod derive;
mod destroy_object;
mod digest;
mod discovery;
mod encapsulate;
mod init_token;
mod encrypt;
mod generate;
mod dispatch;
mod mechanisms;
mod objects;
mod piv_slot;
mod set_pin;
mod sign;
mod template;
mod verify;

pub use dispatch::*;