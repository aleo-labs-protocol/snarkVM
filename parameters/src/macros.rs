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

#[macro_export]
macro_rules! checksum {
    ($bytes: expr) => {{
        use sha2::Digest;
        hex::encode(&sha2::Sha256::digest($bytes))
    }};
}

#[macro_export]
macro_rules! checksum_error {
    ($expected: expr, $candidate: expr) => {
        Err($crate::errors::ParameterError::ChecksumMismatch($expected, $candidate))
    };
}

#[macro_export]
macro_rules! remove_file {
    ($filepath:expr) => {
        // Safely remove the corrupt file, if it exists.
        #[cfg(all(feature = "filesystem", not(feature = "wasm")))]
        if std::path::PathBuf::from(&$filepath).exists() {
            let _removed = std::fs::remove_file(&$filepath);
            #[cfg(not(feature = "no_std_out"))]
            match _removed {
                Ok(()) => println!("Removed {:?}. Please retry the command.", $filepath),
                Err(err) => eprintln!("Failed to remove {:?}: {err}", $filepath),
            }
        }
    };
}

macro_rules! impl_store_and_remote_fetch {
    () => {
        #[cfg(all(feature = "filesystem", not(feature = "wasm")))]
        fn store_bytes(buffer: &[u8], file_path: &std::path::Path) -> Result<(), $crate::errors::ParameterError> {
            use snarkvm_utilities::Write;

            #[cfg(not(feature = "no_std_out"))]
            {
                use colored::*;
                let output = format!("{:>15} - Storing file in {:?}", "Installation", file_path);
                println!("{}", output.dimmed());
            }

            // Ensure the folders up to the file path all exist.
            let mut directory_path = file_path.to_path_buf();
            directory_path.pop();
            let _ = std::fs::create_dir_all(&directory_path)?;

            // Write to `<file name>.param.<process id>.<thread id>.tmp`, then rename it into place,
            // so a concurrent reader sees either no file or the complete file.
            let mut temp_prefix = file_path.file_name().unwrap_or_default().to_owned();
            temp_prefix.push(".param.");
            let mut temp_path = file_path.as_os_str().to_owned();
            temp_path.push(format!(".param.{}.{:?}.tmp", std::process::id(), std::thread::current().id()));
            match std::fs::File::create(&temp_path) {
                Ok(mut file) => {
                    // Sync before the rename, so a crash cannot leave a truncated file under the final name.
                    let written = file.write_all(buffer).and_then(|()| file.sync_all());
                    drop(file);
                    if let Err(error) = written.and_then(|()| std::fs::rename(&temp_path, file_path)) {
                        let _ = std::fs::remove_file(&temp_path);
                        // A concurrent writer stored this file first and removed this temporary file in its cleanup.
                        if file_path.exists() {
                            return Ok(());
                        }
                        return Err(error.into());
                    }
                    // Remove temporary files that writers of this file left behind when they died before the rename.
                    // A writer that dies after this pass leaves its temporary file, and nothing removes it.
                    if let Ok(entries) = std::fs::read_dir(&directory_path) {
                        for entry in entries.flatten() {
                            let name = entry.file_name();
                            let name = name.as_encoded_bytes();
                            if name.starts_with(temp_prefix.as_encoded_bytes()) && name.ends_with(b".tmp") {
                                let _ = std::fs::remove_file(entry.path());
                            }
                        }
                    }
                }
                Err(error) => eprintln!("{}", error),
            }
            Ok(())
        }

        /// Returns an exclusive lock on `<file path>.lock`, waiting while another loader holds it,
        /// or `None` if the lock is unavailable, e.g. on a filesystem without lock support.
        #[cfg(all(feature = "filesystem", not(feature = "wasm"), not(target_env = "sgx")))]
        fn lock_download(file_path: &std::path::Path) -> Option<std::fs::File> {
            std::fs::create_dir_all(file_path.parent()?).ok()?;

            // The lock file is never removed. Removing it lets a waiter that opened it lock the removed file
            // while a new loader locks a new one, and both download.
            let mut lock_path = file_path.as_os_str().to_owned();
            lock_path.push(".lock");
            let file = std::fs::OpenOptions::new().read(true).write(true).create(true).truncate(false).open(lock_path).ok()?;
            match file.try_lock() {
                Ok(()) => Some(file),
                Err(std::fs::TryLockError::WouldBlock) => {
                    #[cfg(not(feature = "no_std_out"))]
                    {
                        use colored::*;
                        let output = format!("{:>15} - Waiting for a concurrent download of {:?}", "Installation", file_path);
                        println!("{}", output.dimmed());
                    }
                    file.lock().ok().map(|()| file)
                }
                Err(std::fs::TryLockError::Error(_)) => None,
            }
        }

        #[cfg(all(feature = "filesystem", not(feature = "wasm"), not(target_env = "sgx")))]
        fn remote_fetch(buffer: &mut Vec<u8>, url: &str) -> Result<(), $crate::errors::ParameterError> {
            use std::io::Read;

            #[cfg(not(feature = "no_std_out"))]
            {
                use colored::*;
                let output = format!("{:>15} - Downloading \"{}\"", "Installation", url);
                println!("{}", output.dimmed());
            }

            use std::time::Duration;
            const CONNECT: Option<Duration> = Some(Duration::from_secs(10));
            const HEADERS: Option<Duration> = Some(Duration::from_secs(30));

            // `CONNECT` covers the DNS lookup, the TCP connect and the TLS handshake (ureq 3.4).
            let agent: ureq::Agent = ureq::Agent::config_builder()
                .max_redirects(10)
                .timeout_resolve(CONNECT)
                .timeout_connect(CONNECT)
                .timeout_send_request(CONNECT)
                .timeout_recv_response(HEADERS)
                .build()
                .into();

            // A mid-body stall is not bounded: ureq 3.4's `timeout_recv_body` is a total budget and these files
            // reach 12.9 GB. A per-chunk bound on `Range` requests would close it.
            let fetch_once = |buffer: &mut Vec<u8>| -> Result<(), ureq::Error> {
                let mut response = agent.get(url).call()?;
                // Read inside the retried unit, so a mid-body failure reaches the retry arms below.
                buffer.clear();
                response.body_mut().as_reader().read_to_end(buffer)?;
                Ok(())
            };

            // Retry up to 3 times on transient errors (5xx, 429, IO, timeout).
            let mut attempts = 3u32;
            loop {
                match fetch_once(buffer) {
                    Ok(()) => break,
                    Err(ureq::Error::StatusCode(code)) if attempts > 0 && (code >= 500 || code == 429) => {
                        attempts -= 1;
                    }
                    Err(ureq::Error::Io(_) | ureq::Error::Timeout(_)) if attempts > 0 => {
                        attempts -= 1;
                    }
                    Err(err) => return Err(err.into()),
                }
            }

            #[cfg(not(feature = "no_std_out"))]
            {
                use colored::*;
                let size_in_megabytes = buffer.len() as u64 / 1_048_576;
                let output = format!("{:>15} - Download complete ({} MB)", "Installation", size_in_megabytes);
                println!("{}", output.dimmed());
            }

            Ok(())
        }

        #[cfg(feature = "wasm")]
        fn remote_fetch(url: &str) -> Result<Vec<u8>, $crate::errors::ParameterError> {
            // Use the browser's XmlHttpRequest object to download the parameter file synchronously.
            //
            // This method blocks the event loop while the parameters are downloaded, and should be
            // executed in a web worker to prevent the main browser window from freezing.
            let xhr = web_sys::XmlHttpRequest::new().map_err(|_| {
                $crate::errors::ParameterError::Wasm("Download failed - XMLHttpRequest object not found".to_string())
            })?;

            // XmlHttpRequest if specified as synchronous cannot use the responseType property. It
            // cannot thus download bytes directly and enforces a text encoding. To get back the
            // original binary, a charset that does not corrupt the original bytes must be used.
            xhr.override_mime_type("octet/binary; charset=ISO-8859-5").unwrap();

            // Initialize and send the request.
            xhr.open_with_async("GET", url, false).map_err(|_| {
                $crate::errors::ParameterError::Wasm(
                    "Download failed - This browser does not support synchronous requests".to_string(),
                )
            })?;
            xhr.send()
                .map_err(|_| $crate::errors::ParameterError::Wasm("Download failed - XMLHttpRequest failed".to_string()))?;

            // Wait for the response in a blocking fashion.
            if xhr.response().is_ok() && xhr.status().unwrap() == 200 {
                // Get the text from the response.
                let rust_text = xhr
                    .response_text()
                    .map_err(|_| $crate::errors::ParameterError::Wasm("XMLHttpRequest failed".to_string()))?
                    .ok_or($crate::errors::ParameterError::Wasm(
                        "The request was successful but no parameters were received".to_string(),
                    ))?;

                // Re-encode the text back into bytes using the chosen encoding.
                use encoding::Encoding;
                encoding::all::ISO_8859_5
                    .encode(&rust_text, encoding::EncoderTrap::Strict)
                    .map_err(|_| $crate::errors::ParameterError::Wasm("Parameter decoding failed".to_string()))
            } else {
                Err($crate::errors::ParameterError::Wasm("Download failed - XMLHttpRequest failed".to_string()))
            }
        }
    };
}

macro_rules! impl_load_bytes_logic_local {
    ($filepath: expr, $buffer: expr, $expected_size: expr, $expected_checksum: expr) => {
        // Ensure the size matches.
        if $expected_size != $buffer.len() {
            remove_file!($filepath);
            return Err($crate::errors::ParameterError::SizeMismatch($expected_size, $buffer.len()));
        }

        // Ensure the checksum matches.
        let candidate_checksum = checksum!($buffer);
        if $expected_checksum != candidate_checksum {
            return checksum_error!($expected_checksum, candidate_checksum);
        }

        return Ok($buffer.to_vec());
    };
}

macro_rules! impl_load_bytes_logic_remote {
    ($remote_urls: expr, $local_dir: expr, $filename: expr, $metadata: expr, $expected_checksum: expr, $expected_size: expr) => {
        cfg_if::cfg_if! {
            if #[cfg(all(feature = "filesystem", not(feature="wasm")))] {
                // Compose the correct file path for the parameter file.
                let mut file_path = aleo_std::aleo_dir();
                file_path.push($local_dir);
                file_path.push($filename);

                // A loader that finds the file missing holds this lock until the file is stored, so the first
                // downloads it and the rest wait, then read and verify the stored file concurrently.
                // A download that stalls blocks every waiting loader until the stalled process exits.
                #[cfg(not(target_env = "sgx"))]
                let lock = if file_path.exists() { None } else { Self::lock_download(&file_path) };

                let buffer = if file_path.exists() {
                    #[cfg(not(target_env = "sgx"))]
                    drop(lock);
                    // Attempts to load the parameter file locally with an absolute path.
                    std::fs::read(&file_path)?
                } else {
                    // Downloads the missing parameters and stores it in the local directory for use.
                    #[cfg(not(feature = "no_std_out"))]
                    {
                        use colored::*;
                        let path = format!("(in {:?})", file_path);
                        eprintln!(
                            "\n⚠️  \"{}\" does not exist. Downloading and storing it {}.\n",
                            $filename, path.dimmed()
                        );
                    }

                    // Load remote file
                    cfg_if::cfg_if!{
                        if #[cfg(all(not(feature = "wasm"), not(target_env = "sgx")))] {
                            // Try each URL in order, falling back to the next if one fails.
                            let remote_urls: &[&str] = &$remote_urls;
                            let mut buffer = vec![];
                            let mut last_error: Option<($crate::errors::ParameterError, &str)> = None;

                            for base_url in remote_urls.iter() {
                                // Remove the previous error (if any).
                                cfg_if::cfg_if!{
                                    if #[cfg(feature = "no_std_out")] {
                                        last_error = None;
                                    } else {
                                        use colored::Colorize;
                                        // If this is a retry, print the previous error as warning.
                                        if let Some((err, url)) = last_error.take() {
                                            eprintln!("{:>15} - {err}", "Warning".yellow());
                                            eprintln!("{:>15} - Failed to fetch from \"{url}\". Trying next source...", "Warning".yellow());
                                         }
                                    }
                                }

                                let url = format!("{}/{}", base_url, $filename);
                                buffer.clear();

                                match Self::remote_fetch(&mut buffer, &url) {
                                    Ok(()) => {
                                        // Ensure the checksum matches.
                                        let candidate_checksum = checksum!(&buffer);
                                        if $expected_checksum == candidate_checksum {
                                            // Success - break out of the loop
                                            break;
                                        } else {
                                            last_error = Some(($crate::errors::ParameterError::ChecksumMismatch(
                                                $expected_checksum.to_string(),
                                                candidate_checksum,
                                            ), base_url));
                                        }
                                    }
                                    Err(err) => {
                                        last_error = Some((err, base_url));
                                    }
                                }
                            }

                            // If all URLs failed, return the last error.
                            if let Some((err, _)) = last_error {
                                return Err(err);
                            }

                            let stored = Self::store_bytes(&buffer, &file_path);
                            drop(lock);
                            match stored {
                                Ok(()) => buffer,
                                Err(_) => {
                                    eprintln!(
                                        "\n❗ Error - Failed to store \"{}\" locally. Please download this file manually and ensure it is stored in {:?}.\n",
                                        $filename, file_path
                                    );
                                    buffer
                                }
                            }
                        } else {
                            return Err($crate::errors::ParameterError::RemoteFetchDisabled);
                        }
                    }
                };

                // Ensure the size matches.
                if $expected_size != buffer.len() {
                    remove_file!(file_path);
                    return Err($crate::errors::ParameterError::SizeMismatch($expected_size, buffer.len()));
                }

                // Ensure the checksum matches.
                let candidate_checksum = checksum!(buffer.as_slice());
                if $expected_checksum != candidate_checksum {
                    remove_file!(file_path);
                    return checksum_error!($expected_checksum, candidate_checksum)
                }
                return Ok(buffer);
            } else {
                cfg_if::cfg_if! {
                    if #[cfg(feature = "wasm")] {
                        // This arm keeps the download in memory and stores no file, so it takes no download lock,
                        // and concurrent loaders each download the file.
                        // Try each URL in order, falling back to the next if one fails.
                        let remote_urls: &[&str] = &$remote_urls;
                        let mut buffer = vec![];
                        let mut last_error: Option<$crate::errors::ParameterError> = None;

                        for base_url in remote_urls.iter() {
                            let url = format!("{}/{}", base_url, $filename);

                            match Self::remote_fetch(&url) {
                                Ok(fetched_buffer) => {
                                    // Ensure the checksum matches.
                                    let candidate_checksum = checksum!(&fetched_buffer);
                                    if $expected_checksum == candidate_checksum {
                                        buffer = fetched_buffer;
                                        last_error = None;
                                        break;
                                    } else {
                                        last_error = Some($crate::errors::ParameterError::ChecksumMismatch(
                                            $expected_checksum.to_string(),
                                            candidate_checksum,
                                        ));
                                    }
                                }
                                Err(e) => {
                                    last_error = Some(e);
                                }
                            }
                        }

                        // If all URLs failed, return the last error.
                        if let Some(e) = last_error {
                            return Err(e);
                        }

                        // Ensure the size matches.
                        if $expected_size != buffer.len() {
                            return Err($crate::errors::ParameterError::SizeMismatch($expected_size, buffer.len()));
                        }

                        return Ok(buffer)
                    } else {
                        let _ = (&$remote_urls, &$filename, &$expected_size);
                        return Err($crate::errors::ParameterError::FilesystemDisabled);
                    }
                }
            }
        }
    }
}

#[macro_export]
macro_rules! impl_local {
    ($name: ident, $local_dir: expr, $fname: tt, "usrs") => {
        #[derive(Clone, Debug, PartialEq, Eq)]
        pub struct $name;

        impl $name {
            pub const METADATA: &'static str = include_str!(concat!($local_dir, $fname, ".metadata"));

            pub fn load_bytes() -> Result<Vec<u8>, $crate::errors::ParameterError> {
                let metadata: serde_json::Value = serde_json::from_str(Self::METADATA).expect("Metadata was not well-formatted");
                let expected_checksum: String = metadata["checksum"].as_str().expect("Failed to parse checksum").to_string();
                let expected_size: usize = metadata["size"].to_string().parse().expect("Failed to retrieve the file size");

                let _filepath = concat!($local_dir, $fname, ".", "usrs");
                let buffer = include_bytes!(concat!($local_dir, $fname, ".", "usrs"));

                impl_load_bytes_logic_local!(_filepath, buffer, expected_size, expected_checksum);
            }
        }

        paste::item! {
            #[cfg(test)]
            #[test]
            fn [< test_ $fname _usrs >]() {
                // Print error messages if loading fails. This can be simplified once assert_matches! is stable.
                if let Err(err) = $name::load_bytes() {
                    panic!("Failed to load bytes: {err}");
                }
            }
        }
    };
    ($name: ident, $local_dir: expr, $fname: tt, $ftype: tt, $credits_version: tt) => {
        #[derive(Clone, Debug, PartialEq, Eq)]
        pub struct $name;

        impl $name {
            pub const METADATA: &'static str = include_str!(concat!($local_dir, $credits_version, "/", $fname, ".metadata"));

            pub fn load_bytes() -> Result<Vec<u8>, $crate::errors::ParameterError> {
                let metadata: serde_json::Value = serde_json::from_str(Self::METADATA).expect("Metadata was not well-formatted");
                let expected_checksum: String =
                    metadata[concat!($ftype, "_checksum")].as_str().expect("Failed to parse checksum").to_string();
                let expected_size: usize =
                    metadata[concat!($ftype, "_size")].to_string().parse().expect("Failed to retrieve the file size");

                let _filepath = concat!($local_dir, $credits_version, "/", $fname, ".", $ftype);
                let buffer = include_bytes!(concat!($local_dir, $credits_version, "/", $fname, ".", $ftype));

                impl_load_bytes_logic_local!(_filepath, buffer, expected_size, expected_checksum);
            }
        }

        paste::item! {
            #[cfg(test)]
            #[test]
            fn [< test_ $credits_version _ $fname _ $ftype >]() {
                if let Err(err) = $name::load_bytes() {
                    panic!("Failed to load bytes: {err}");
                }
            }
        }
    };
}

#[macro_export]
macro_rules! impl_remote {
    ($name: ident, $remote_url: expr, $local_dir: expr, $fname: tt, "usrs") => {
        pub struct $name;

        impl $name {
            pub const METADATA: &'static str = include_str!(concat!($local_dir, $fname, ".metadata"));

            impl_store_and_remote_fetch!();

            pub fn load_bytes() -> Result<Vec<u8>, $crate::errors::ParameterError> {
                let metadata: serde_json::Value = serde_json::from_str(Self::METADATA).expect("Metadata was not well-formatted");
                let expected_checksum: String = metadata["checksum"].as_str().expect("Failed to parse checksum").to_string();
                let expected_size: usize = metadata["size"].to_string().parse().expect("Failed to retrieve the file size");

                // Construct the versioned filename.
                let filename = match expected_checksum.get(0..7) {
                    Some(sum) => format!("{}.{}.{}", $fname, "usrs", sum),
                    _ => format!("{}.{}", $fname, "usrs"),
                };

                impl_load_bytes_logic_remote!($remote_url, $local_dir, &filename, metadata, expected_checksum, expected_size);
            }
        }
        paste::item! {
            #[cfg(all(test, feature = "filesystem"))]
            #[test]
            fn [< test_ $fname _usrs >]() {
                assert!($name::load_bytes().is_ok());
            }
        }
    };
    ($name: ident, $remote_url: expr, $local_dir: expr, $fname: tt, $ftype: tt, $credits_version: tt) => {
        pub struct $name;

        impl $name {
            pub const METADATA: &'static str = include_str!(concat!($local_dir, $credits_version, "/", $fname, ".metadata"));

            impl_store_and_remote_fetch!();

            pub fn load_bytes() -> Result<Vec<u8>, $crate::errors::ParameterError> {
                let metadata: serde_json::Value = serde_json::from_str(Self::METADATA).expect("Metadata was not well-formatted");
                let expected_checksum: String =
                    metadata[concat!($ftype, "_checksum")].as_str().expect("Failed to parse checksum").to_string();
                let expected_size: usize =
                    metadata[concat!($ftype, "_size")].to_string().parse().expect("Failed to retrieve the file size");

                // Construct the versioned filename.
                let filename = match expected_checksum.get(0..7) {
                    Some(sum) => format!("{}.{}.{}", $fname, $ftype, sum),
                    _ => format!("{}.{}", $fname, $ftype),
                };

                impl_load_bytes_logic_remote!($remote_url, $local_dir, &filename, metadata, expected_checksum, expected_size);
            }

            /// Checks `buffer` against this file's size and checksum in `METADATA`.
            pub fn verify_bytes(buffer: &[u8]) -> Result<(), $crate::errors::ParameterError> {
                let metadata: serde_json::Value = serde_json::from_str(Self::METADATA).expect("Metadata was not well-formatted");
                let expected_checksum: String =
                    metadata[concat!($ftype, "_checksum")].as_str().expect("Failed to parse checksum").to_string();
                let expected_size: usize =
                    metadata[concat!($ftype, "_size")].to_string().parse().expect("Failed to retrieve the file size");

                // Ensure the size matches.
                if buffer.len() != expected_size {
                    return Err($crate::errors::ParameterError::SizeMismatch(expected_size, buffer.len()));
                }

                // Ensure the checksum matches.
                let candidate_checksum = checksum!(buffer);
                if expected_checksum != candidate_checksum {
                    return checksum_error!(expected_checksum, candidate_checksum);
                }
                Ok(())
            }
        }

        paste::item! {
            #[cfg(all(test, feature = "filesystem"))]
            #[test]
            fn [< test_ $credits_version _ $fname _ $ftype >]() {
                if let Err(err) = $name::load_bytes() {
                    panic!("Failed to load bytes: {err}");
                }
            }
        }
    };
}
