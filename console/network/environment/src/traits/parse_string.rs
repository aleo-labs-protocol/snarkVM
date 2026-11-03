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

/// From <https://github.com/Geal/nom/blob/main/examples/string.rs>
pub mod string_parser {
    /// This example shows an example of how to parse an escaped string. The
    /// rules for the string are similar to JSON and rust. A string is:
    ///
    /// - Enclosed by double quotes
    /// - Can contain any raw unescaped code point besides \ and "
    /// - Matches the following escape sequences: \b, \f, \n, \r, \t, \", \\, \/
    /// - Matches code points like Rust: \u{XXXX}, where XXXX can be up to 6
    ///   hex characters
    /// - an escape followed by whitespace consumes all whitespace between the
    ///   escape and the next non-whitespace character
    use nom::{
        Err::Error,
        IResult,
        branch::alt,
        bytes::streaming::{is_not, take_while_m_n},
        character::streaming::{char, multispace1},
        combinator::{map, map_opt, map_res, value, verify},
        error::{ErrorKind, FromExternalError, ParseError},
        multi::fold_many0,
        sequence::{delimited, preceded},
    };

    /// Checks for supported code points.
    ///
    /// We regard the following characters as safe:
    /// - Horizontal tab (code 9).
    /// - Line feed (code 10).
    /// - Carriage return (code 13).
    /// - Space (code 32).
    /// - Visible ASCII (codes 33-126).
    /// - Non-ASCII Unicode scalar values (codes 128+) except
    ///   * bidi embeddings, overrides and their termination (codes U+202A-U+202E)
    ///   * isolates (codes U+2066-U+2069)
    ///
    /// The Unicode bidi characters are well-known for presenting Trojan Source dangers.
    /// The ASCII backspace (code 8) can be also used to make text look different from what it is,
    /// and a similar danger may apply to delete (126).
    /// Other ASCII control characters
    /// (except for horizontal tab, space, line feed, and carriage return, which are allowed)
    /// may or may not present dangers, but we see no good reason for allowing them.
    /// At some point we may want to disallow additional non-ASCII characters,
    /// if we see no good reason to allow them.
    ///
    /// Note that we say 'Unicode scalar values' above,
    /// because we read UTF-8-decoded characters,
    /// and thus we will never encounter surrogate code points,
    /// and we do not need to explicitly exclude them in this function.
    pub fn is_char_supported(c: char) -> bool {
        !is_char_unsupported(c)
    }

    /// Checks for unsupported "invisible" code points.
    fn is_char_unsupported(c: char) -> bool {
        let code = c as u32;

        // A quick early return, as anything above is supported.
        if code > 0x2069 {
            return false;
        }

        // A "divide and conquer" approach for greater performance; ranges are
        // checked before single values and all the comparisons get "reused".
        if code < 0x202a {
            if code <= 31 { !(9..14).contains(&code) || code == 11 || code == 12 } else { code == 127 }
        } else {
            code <= 0x202e || code >= 0x2066
        }
    }

    /// Parse a Unicode sequence, of the form u{XXXX}, where XXXX is 1 to 6
    /// hexadecimal numerals. We will combine this later with [parse_escaped_char]
    /// to parse sequences like \u{00AC}.
    fn parse_unicode<'a, E>(input: &'a str) -> IResult<&'a str, char, E>
    where
        E: ParseError<&'a str> + FromExternalError<&'a str, std::num::ParseIntError>,
    {
        // `take_while_m_n` parses between `m` and `n` bytes (inclusive) that match
        // a predicate. `parse_hex` here parses between 1 and 6 hexadecimal numerals.
        let parse_hex = take_while_m_n(1, 6, |c: char| c.is_ascii_hexdigit());

        // `preceded` takes a prefix parser, and if it succeeds, returns the result
        // of the body parser. In this case, it parses u{XXXX}.
        let parse_delimited_hex = preceded(
            char('u'),
            // `delimited` is like `preceded`, but it parses both a prefix and a suffix.
            // It returns the result of the middle parser. In this case, it parses
            // {XXXX}, where XXXX is 1 to 6 hex numerals, and returns XXXX
            delimited(char('{'), parse_hex, char('}')),
        );

        // `map_res` takes the result of a parser and applies a function that returns
        // a Result. In this case we take the hex bytes from parse_hex and attempt to
        // convert them to a u32.
        let parse_u32 = map_res(parse_delimited_hex, move |hex| u32::from_str_radix(hex, 16));

        // map_opt is like map_res, but it takes an Option instead of a Result. If
        // the function returns None, map_opt returns an error. In this case, because
        // not all u32 values are valid Unicode code points, we have to fallibly
        // convert to char with from_u32.
        map_opt(parse_u32, std::char::from_u32)(input)
    }

    /// Parse an escaped character: \n, \t, \r, \u{00AC}, etc.
    fn parse_escaped_char<'a, E>(input: &'a str) -> IResult<&'a str, char, E>
    where
        E: ParseError<&'a str> + FromExternalError<&'a str, std::num::ParseIntError>,
    {
        preceded(
            char('\\'),
            // `alt` tries each parser in sequence, returning the result of
            // the first successful match
            alt((
                parse_unicode,
                // The `value` parser returns a fixed value (the first argument) if its
                // parser (the second argument) succeeds. In these cases, it looks for
                // the marker characters (n, r, t, etc.) and returns the matching
                // character (\n, \r, \t, etc.).
                value('\n', char('n')),
                value('\r', char('r')),
                value('\t', char('t')),
                value('\u{08}', char('b')),
                value('\u{0C}', char('f')),
                value('\\', char('\\')),
                value('/', char('/')),
                value('"', char('"')),
            )),
        )(input)
    }

    /// Parse a backslash, followed by any amount of whitespace. This is used later
    /// to discard any escaped whitespace.
    fn parse_escaped_whitespace<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, &'a str, E> {
        preceded(char('\\'), multispace1)(input)
    }

    /// Parse a non-empty block of text that doesn't include \ or "
    fn parse_literal<'a, E: ParseError<&'a str>>(input: &'a str) -> IResult<&'a str, &'a str, E> {
        // Return an error if the literal contains an unsupported code point.
        if input.chars().any(is_char_unsupported) {
            return Err(Error(E::from_error_kind("String literal contains invalid codepoint", ErrorKind::Char)));
        }

        // `is_not` parses a string of 0 or more characters that aren't one of the
        // given characters.
        let not_quote_slash = is_not("\"\\");

        // `verify` runs a parser, then runs a verification function on the output of
        // the parser. The verification function accepts output only if it
        // returns true. In this case, we want to ensure that the output of is_not
        // is non-empty.
        verify(not_quote_slash, |s: &str| !s.is_empty())(input)
    }

    /// A string fragment contains a fragment of a string being parsed: either
    /// a non-empty Literal (a series of non-escaped characters), a single
    /// parsed escaped character, or a block of escaped whitespace.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum StringFragment<'a> {
        Literal(&'a str),
        EscapedChar(char),
        EscapedWS,
    }

    /// Combine parse_literal, parse_escaped_whitespace, and parse_escaped_char
    /// into a StringFragment.
    fn parse_fragment<'a, E>(input: &'a str) -> IResult<&'a str, StringFragment<'a>, E>
    where
        E: ParseError<&'a str> + FromExternalError<&'a str, std::num::ParseIntError>,
    {
        alt((
            // The `map` combinator runs a parser, then applies a function to the output
            // of that parser.
            map(parse_literal, StringFragment::Literal),
            map(parse_escaped_char, StringFragment::EscapedChar),
            value(StringFragment::EscapedWS, parse_escaped_whitespace),
        ))(input)
    }

    /// Parse a string. Use a loop of parse_fragment and push all of the fragments
    /// into an output string.
    pub fn parse_string<'a, E>(input: &'a str) -> IResult<&'a str, String, E>
    where
        E: ParseError<&'a str> + FromExternalError<&'a str, std::num::ParseIntError>,
    {
        // fold_many0 is the equivalent of iterator::fold. It runs a parser in a loop,
        // and for each output value, calls a folding function on each output value.
        let build_string = fold_many0(
            // Our parser function– parses a single string fragment
            parse_fragment,
            // Our init value, an empty string
            String::new,
            // Our folding function. For each fragment, append the fragment to the
            // string.
            |mut string, fragment| {
                match fragment {
                    StringFragment::Literal(s) => string.push_str(s),
                    StringFragment::EscapedChar(c) => string.push(c),
                    StringFragment::EscapedWS => {}
                }
                string
            },
        );

        // Finally, parse the string. Note that, if `build_string` could accept a raw
        // " character, the closing delimiter " would never match. When using
        // `delimited` with a looping parser (like fold_many0), be sure that the
        // loop won't accidentally match your closing delimiter!
        delimited(char('"'), build_string, char('"'))(input)
    }
}

#[test]
fn test_parse_string() {
    // to use parse_string_wrapper instead of string_parser::parse_string::<nom::error::VerboseError<&str>> in the tests below:
    fn parse_string_wrapper(input: &str) -> crate::ParserResult<'_, String> {
        string_parser::parse_string(input)
    }

    // tests some correct string literals:
    assert_eq!(("", String::from("")), parse_string_wrapper("\"\"").unwrap());
    assert_eq!(("", String::from("abc")), parse_string_wrapper("\"abc\"").unwrap());
    assert_eq!((" and more", String::from("abc")), parse_string_wrapper("\"abc\" and more").unwrap());
    assert_eq!(("", String::from("\r")), parse_string_wrapper("\"\r\"").unwrap());
    assert_eq!(("", String::from("4\u{4141}x\x09")), parse_string_wrapper("\"4\u{4141}x\x09\"").unwrap());

    // test rejection of disallowed characters:
    assert!(parse_string_wrapper("\"hel\x08lo\"").is_err());
    assert!(parse_string_wrapper("\"hel\x1flo\"").is_err());
    assert!(parse_string_wrapper("\"hel\u{2069}lo\"").is_err());
}
