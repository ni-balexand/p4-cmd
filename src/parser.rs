use std::char;
use std::num;
use std::str;

use nom;

use error;

fn is_newline(c: u8) -> bool {
    let c = char::from_u32(u32::from(c));
    c.map(|c| c == '\n' || c == '\r').unwrap_or(false)
}

// unsafe: Assumes `input` is ASCII
unsafe fn i32_from_bytes(input: &[u8]) -> Result<i32, num::ParseIntError> {
    // nom ensured `input` is only ASCII
    let input = str::from_utf8_unchecked(input);

    input.parse()
}

// unsafe: Assumes `input` is ASCII
unsafe fn i64_from_bytes(input: &[u8]) -> Result<i64, num::ParseIntError> {
    // nom ensured `input` is only ASCII
    let input = str::from_utf8_unchecked(input);

    input.parse()
}

// unsafe: Assumes `input` is ASCII
unsafe fn usize_from_bytes(input: &[u8]) -> Result<usize, num::ParseIntError> {
    // nom ensured `input` is only ASCII
    let input = str::from_utf8_unchecked(input);

    input.parse()
}

fn str_from_bytes(input: &[u8]) -> Result<&str, str::Utf8Error> {
    let input = str::from_utf8(input)?;

    Ok(input)
}

pub fn error_to_item<T>(e: Error) -> error::Item<T> {
    error::Item::Message(error::Message::new(
        error::MessageLevel::Error,
        e.msg.to_owned(),
    ))
}

pub fn info_to_item<T>(e: Info) -> error::Item<T> {
    error::Item::Message(error::Message::new(
        error::MessageLevel::Info,
        e.msg.to_owned(),
    ))
}

pub fn exit_to_item<T>(e: Exit) -> error::Item<T> {
    error::Item::Error(error::OperationError::new(e.code))
}

pub fn data_to_item<T>(d: T) -> error::Item<T> {
    error::Item::Data(d)
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Newline;

named!(pub newline<&[u8], Newline>,
    alt!(
        // NOTE: The "\r\n" parser has to be before "\r",
        // otherwise Windows newlines will match on "\r",
        // and the \n will not be consumed by the parser.
        value!(Newline, tag!(b"\r\n")) |
        value!(Newline, tag!(b"\n")) |
        value!(Newline, tag!(b"\r"))
    )
);

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Exit {
    pub(crate) code: i32,
}

fn exit_from_bytes(input: &[u8]) -> Result<Exit, num::ParseIntError> {
    // nom ensured `input` is only ASCII
    let code = unsafe { i32_from_bytes(input)? };

    Ok(Exit { code })
}

named!(pub exit<&[u8], Exit>,
    map_res!(terminated!(preceded!(tag!(b"exit: "), take_while!(nom::is_digit)), newline), exit_from_bytes)
);

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Error<'a> {
    pub(crate) msg: &'a str,
}

fn error_from_bytes(input: &[u8]) -> Result<Error, str::Utf8Error> {
    let msg = str_from_bytes(input)?;
    Ok(Error { msg })
}

named!(pub error<&[u8], Error>,
    map_res!(terminated!(preceded!(alt!(tag!(b"error: ") | tag!(b"warning: ")), take_till!(is_newline)), newline), error_from_bytes)
);

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Info<'a> {
    pub(crate) msg: &'a str,
}

fn info_from_bytes(input: &[u8]) -> Result<Info, str::Utf8Error> {
    let msg = str_from_bytes(input)?;
    Ok(Info { msg })
}

named!(pub info<&[u8], Info>,
    map_res!(terminated!(preceded!(tag!(b"info: "), take_till!(is_newline)), newline), info_from_bytes)
);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DepotFile<'a> {
    pub(crate) path: &'a str,
}

fn depot_file_from_bytes(input: &[u8]) -> Result<DepotFile, str::Utf8Error> {
    let path = str_from_bytes(input)?;
    Ok(DepotFile { path })
}

named!(pub depot_file<&[u8], DepotFile>,
    map_res!(terminated!(preceded!(tag!(b"info1: depotFile "), take_till!(is_newline)), newline), depot_file_from_bytes)
);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientFile<'a> {
    pub(crate) path: &'a str,
}

fn client_file_from_bytes(input: &[u8]) -> Result<ClientFile, str::Utf8Error> {
    let path = str_from_bytes(input)?;
    Ok(ClientFile { path })
}

named!(pub client_file<&[u8], ClientFile>,
    map_res!(terminated!(preceded!(tag!(b"info1: clientFile "), take_till!(is_newline)), newline), client_file_from_bytes)
);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Path<'a> {
    pub(crate) path: &'a str,
}

fn path_from_bytes(input: &[u8]) -> Result<Path, str::Utf8Error> {
    let path = str_from_bytes(input)?;
    Ok(Path { path })
}

named!(pub path<&[u8], Path>,
    map_res!(terminated!(preceded!(tag!(b"info1: path "), take_till!(is_newline)), newline), path_from_bytes)
);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dir<'a> {
    pub(crate) dir: &'a str,
}

fn dir_from_bytes(input: &[u8]) -> Result<Dir, str::Utf8Error> {
    let dir = str_from_bytes(input)?;
    Ok(Dir { dir })
}

named!(pub dir<&[u8], Dir>,
    map_res!(terminated!(preceded!(tag!(b"info1: dir "), take_till!(is_newline)), newline), dir_from_bytes)
);

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Rev {
    pub(crate) rev: usize,
}

fn rev_from_bytes(input: &[u8]) -> Result<Rev, num::ParseIntError> {
    // nom ensured `input` is only ASCII
    let rev = unsafe { usize_from_bytes(input)? };

    Ok(Rev { rev })
}

named!(pub rev<&[u8], Rev>,
    map_res!(terminated!(preceded!(tag!(b"info1: rev "), take_while!(nom::is_digit)), newline), rev_from_bytes)
);

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Change {
    pub(crate) change: usize,
}

fn change_from_bytes(input: &[u8]) -> Result<Change, num::ParseIntError> {
    // nom ensured `input` is only ASCII
    let change = unsafe { usize_from_bytes(input)? };

    Ok(Change { change })
}

named!(pub change<&[u8], Change>,
    map_res!(terminated!(preceded!(tag!(b"info1: change "), take_while!(nom::is_digit)), newline), change_from_bytes)
);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Action<'a> {
    pub(crate) action: &'a str,
}

fn action_from_bytes(input: &[u8]) -> Result<Action, str::Utf8Error> {
    let action = str_from_bytes(input)?;
    Ok(Action { action })
}

named!(pub action<&[u8], Action>,
    map_res!(terminated!(preceded!(tag!(b"info1: action "), take_till!(is_newline)), newline), action_from_bytes)
);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileType<'a> {
    pub(crate) ft: &'a str,
}

fn file_type_from_bytes(input: &[u8]) -> Result<FileType, str::Utf8Error> {
    let ft = str_from_bytes(input)?;
    Ok(FileType { ft })
}

named!(pub file_type<&[u8], FileType>,
    map_res!(terminated!(preceded!(tag!(b"info1: type "), take_till!(is_newline)), newline), file_type_from_bytes)
);

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Time {
    pub(crate) time: i64,
}

fn time_from_bytes(input: &[u8]) -> Result<Time, num::ParseIntError> {
    // nom ensured `input` is only ASCII
    let time = unsafe { i64_from_bytes(input)? };

    Ok(Time { time })
}

named!(pub time<&[u8], Time>,
    map_res!(terminated!(preceded!(tag!(b"info1: time "), take_while!(nom::is_digit)), newline), time_from_bytes)
);

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct FileSize {
    pub(crate) size: usize,
}

fn file_size_from_bytes(input: &[u8]) -> Result<FileSize, num::ParseIntError> {
    // nom ensured `input` is only ASCII
    let size = unsafe { usize_from_bytes(input)? };

    Ok(FileSize { size })
}

named!(pub file_size<&[u8], FileSize>,
    map_res!(terminated!(preceded!(tag!(b"info1: fileSize "), take_while!(nom::is_digit)), newline), file_size_from_bytes)
);

fn ignore_from_bytes(_input: &[u8]) -> Result<(), num::ParseIntError> {
    Ok(())
}

named!(pub ignore_info1<&[u8], ()>,
    map_res!(terminated!(preceded!(tag!(b"info1: "), take_till!(is_newline)), newline), ignore_from_bytes)
);

fn text_from_bytes(input: &[u8]) -> Result<String, str::Utf8Error> {
    let text = str_from_bytes(input)?.to_owned();

    Ok(text)
}

named!(pub text<&[u8], String>,
    map_res!(terminated!(preceded!(tag!(b"text: "), take_till!(is_newline)), newline), text_from_bytes)
);

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn parse_exit_success() {
        let expected_remaining: &[u8] = b"";
        assert_eq!(
            exit(b"exit: 0\n"),
            Ok((expected_remaining, Exit { code: 0 }))
        );
    }

    #[test]
    fn parse_exit_positive() {
        let expected_remaining: &[u8] = b"";
        assert_eq!(
            exit(b"exit: 1\n"),
            Ok((expected_remaining, Exit { code: 1 }))
        );
    }

    #[test]
    fn parse_error() {
        let expected_remaining: &[u8] = b"";
        assert_eq!(
            error(b"error: .tags - no such file(s).\n"),
            Ok((
                expected_remaining,
                Error {
                    msg: ".tags - no such file(s)."
                }
            ))
        );
    }

    #[test]
    fn parse_depot_file() {
        let expected_remaining: &[u8] = b"";
        assert_eq!(
            depot_file(b"info1: depotFile //depot/dir/file\n"),
            Ok((
                expected_remaining,
                DepotFile {
                    path: "//depot/dir/file"
                }
            ))
        );
    }

    #[test]
    fn parse_client_file() {
        let expected_remaining: &[u8] = b"";
        assert_eq!(
            client_file(b"info1: clientFile //client/depot/dir/file\n"),
            Ok((
                expected_remaining,
                ClientFile {
                    path: "//client/depot/dir/file"
                }
            ))
        );
    }

    #[test]
    fn parse_path() {
        let expected_remaining: &[u8] = b"";
        assert_eq!(
            path(b"info1: path /home/user/depot/dir/file\n"),
            Ok((
                expected_remaining,
                Path {
                    path: "/home/user/depot/dir/file"
                }
            ))
        );
    }

    #[test]
    fn parse_dir() {
        let expected_remaining: &[u8] = b"";
        assert_eq!(
            dir(b"info1: dir //depot/dir\n"),
            Ok((expected_remaining, Dir { dir: "//depot/dir" }))
        );
    }

    #[test]
    fn parse_rev() {
        let expected_remaining: &[u8] = b"";
        assert_eq!(
            rev(b"info1: rev 42\n"),
            Ok((expected_remaining, Rev { rev: 42 }))
        );
    }

    #[test]
    fn parse_change() {
        let expected_remaining: &[u8] = b"";
        assert_eq!(
            change(b"info1: change 42\n"),
            Ok((expected_remaining, Change { change: 42 }))
        );
    }

    #[test]
    fn parse_action() {
        let expected_remaining: &[u8] = b"";
        assert_eq!(
            action(b"info1: action move/add\n"),
            Ok((expected_remaining, Action { action: "move/add" }))
        );
    }

    #[test]
    fn parse_file_type() {
        let expected_remaining: &[u8] = b"";
        assert_eq!(
            file_type(b"info1: type text\n"),
            Ok((expected_remaining, FileType { ft: "text" }))
        );
    }

    #[test]
    fn parse_file_size() {
        let expected_remaining: &[u8] = b"";
        assert_eq!(
            file_size(b"info1: fileSize 42\n"),
            Ok((expected_remaining, FileSize { size: 42 }))
        );
    }

    #[test]
    fn parse_windows_newline() {
        let expected_remaining: &[u8] = b"";
        assert_eq!(
            exit(b"exit: 0\r\n"),
            Ok((expected_remaining, Exit { code: 0 }))
        );
    }
}
