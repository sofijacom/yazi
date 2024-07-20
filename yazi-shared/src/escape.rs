//! Escape characters that may have special meaning in a shell, including
//! spaces. This is a modified version of the [`shell-escape`] crate and [`this
//! PR`].
//!
//! [`shell-escape`]: https://crates.io/crates/shell-escape
//! [`this PR`]: https://github.com/sfackler/shell-escape/pull/9

#[cfg(unix)]
mod unix {
	use std::{borrow::Cow, ffi::{OsStr, OsString}, os::unix::ffi::{OsStrExt, OsStringExt}};

	pub fn escape(s: &OsStr) -> Cow<'_, OsStr> {
		let bytes = s.as_bytes();
		if !bytes.is_empty() && bytes.iter().copied().all(allowed) {
			return Cow::Borrowed(s);
		}

		let mut escaped = Vec::with_capacity(bytes.len() + 2);
		escaped.push(b'\'');

		for &b in bytes {
			match b {
				b'\'' | b'!' => {
					escaped.reserve(4);
					escaped.push(b'\'');
					escaped.push(b'\\');
					escaped.push(b);
					escaped.push(b'\'');
				}
				_ => escaped.push(b),
			}
		}

		escaped.push(b'\'');
		OsString::from_vec(escaped).into()
	}

	fn allowed(b: u8) -> bool {
		matches!(b, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'=' | b'/' | b',' | b'.' | b'+')
	}

	#[cfg(test)]
	#[test]
	fn test_escape() {
		fn from_str(input: &str, expected: &str) { from_bytes(input.as_bytes(), expected.as_bytes()) }

		fn from_bytes(input: &[u8], expected: &[u8]) {
			let input_os_str = OsStr::from_bytes(input);
			let observed_os_str = escape(input_os_str);
			let expected_os_str = OsStr::from_bytes(expected);
			assert_eq!(observed_os_str, expected_os_str);
		}

		from_str("", r#"''"#);
		from_str(" ", r#"' '"#);
		from_str("*", r#"'*'"#);

		from_str("--aaa=bbb-ccc", "--aaa=bbb-ccc");
		from_str(r#"--features="default""#, r#"'--features="default"'"#);
		from_str("linker=gcc -L/foo -Wl,bar", r#"'linker=gcc -L/foo -Wl,bar'"#);

		from_str(
			"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_=/,.+",
			"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_=/,.+",
		);
		from_str(r#"'!\$`\\\n "#, r#"''\'''\!'\$`\\\n '"#);

		from_bytes(&[0x66, 0x6f, 0x80, 0x6f], &[b'\'', 0x66, 0x6f, 0x80, 0x6f, b'\'']);
	}
}

#[cfg(windows)]
mod windows {
	use std::{borrow::Cow, ffi::{OsStr, OsString}, iter::repeat, os::windows::ffi::{OsStrExt, OsStringExt}};

	pub fn escape(s: &OsStr) -> Cow<'_, OsStr> {
		let wide = s.encode_wide();
		if !s.is_empty() && !wide.clone().into_iter().any(disallowed) {
			return Cow::Borrowed(s);
		}

		let mut escaped: Vec<u16> = Vec::with_capacity(s.len() + 2);
		escaped.push(b'"' as _);

		let mut chars = wide.into_iter().peekable();
		loop {
			let mut slashes = 0;
			while chars.next_if_eq(&(b'\\' as _)).is_some() {
				slashes += 1;
			}
			match chars.next() {
				Some(c) if c == b'"' as _ => {
					escaped.reserve(slashes * 2 + 2);
					escaped.extend(repeat(b'\\' as u16).take(slashes * 2 + 1));
					escaped.push(b'"' as _);
				}
				Some(c) => {
					escaped.reserve(slashes + 1);
					escaped.extend(repeat(b'\\' as _).take(slashes));
					escaped.push(c);
				}
				None => {
					escaped.reserve(slashes * 2);
					escaped.extend(repeat(b'\\' as _).take(slashes * 2));
					break;
				}
			}
		}

		escaped.push(b'"' as _);
		OsString::from_wide(&escaped).into()
	}

	pub fn disallowed(b: u16) -> bool {
		match char::from_u32(b as u32) {
			Some(c) => matches!(c, ' ' | '"' | '\n' | '\t'),
			None => true,
		}
	}

	#[cfg(test)]
	#[test]
	fn test_escape() {
		fn from_str(input: &str, expected: &str) {
			let binding = OsString::from(input);
			let input_os_str = binding.as_os_str();
			let binding = OsString::from(expected);
			let expected_os_str = binding.as_os_str();
			let observed_os_str = escape(input_os_str);
			assert_eq!(observed_os_str, expected_os_str);
		}

		fn from_bytes(input: &[u16], expected: &[u16]) {
			let binding = OsString::from_wide(input);
			let input_os_str = binding.as_os_str();
			let binding = OsString::from_wide(expected);
			let expected_os_str = binding.as_os_str();
			let observed_os_str = escape(input_os_str);
			assert_eq!(observed_os_str, expected_os_str);
		}

		from_str("", r#""""#);
		from_str(r#""""#, r#""\"\"""#);

		from_str("--aaa=bbb-ccc", "--aaa=bbb-ccc");
		from_str(r#"\path\to\my documents\"#, r#""\path\to\my documents\\""#);

		from_str(r#"--features="default""#, r#""--features=\"default\"""#);
		from_str(r#""--features=\"default\"""#, r#""\"--features=\\\"default\\\"\"""#);
		from_str("linker=gcc -L/foo -Wl,bar", r#""linker=gcc -L/foo -Wl,bar""#);

		from_bytes(&[0x1055, 0x006e, 0x0069, 0x0063, 0x006f, 0x0064, 0x0065], &[
			0x1055, 0x006e, 0x0069, 0x0063, 0x006f, 0x0064, 0x0065,
		]);
		from_bytes(&[0xd801, 0x006e, 0x0069, 0x0063, 0x006f, 0x0064, 0x0065], &[
			b'"' as u16,
			0xd801,
			0x006e,
			0x0069,
			0x0063,
			0x006f,
			0x0064,
			0x0065,
			b'"' as u16,
		]);
	}
}
