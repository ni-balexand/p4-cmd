use std::vec;

use error;
use p4;

/// Show how file names are mapped by the client view
///
/// Where shows how the specified files are mapped by the client view.
/// For each argument, three names are produced: the name in the depot,
/// the name on the client in Perforce syntax, and the name on the client
/// in local syntax.
///
/// If the file parameter is omitted, the mapping for all files in the
/// current directory and below) is returned.
///
/// Note that 'p4 where' does not determine where any real files reside.
/// It only displays the locations that are mapped by the client view.
///
/// # Examples
///
/// ```rust,no_run
/// let p4 = p4_cmd::P4::new();
/// let files = p4.where_().file("//depot/dir/*").run();
/// for file in files {
///     println!("{:?}", file);
/// }
/// ```
#[derive(Debug, Clone)]
pub struct Where<'p, 'f> {
    connection: &'p p4::P4,
    file: Vec<&'f str>,
}

impl<'p, 'f> Where<'p, 'f> {
    pub fn new(connection: &'p p4::P4) -> Self {
        Self {
            connection: connection,
            file: vec![],
        }
    }

    /// Restrict the operation to the specified path.
    pub fn file(mut self, file: &'f str) -> Self {
        self.file.push(file);
        self
    }

    /// Run the `where` command.
    pub fn run(self) -> FileIter {
        let mut cmd = self.connection.connect();
        cmd.arg("where");
        for file in self.file {
            cmd.arg(file);
        }
        let data = cmd.output().unwrap();
        let (_remains, (mut items, exit)) = where_parser::where_(&data.stdout).unwrap();
        items.push(exit);
        FileIter(items.into_iter())
    }
}

pub type FileItem = error::Item<File>;

#[derive(Debug)]
pub struct FileIter(vec::IntoIter<FileItem>);

impl Iterator for FileIter {
    type Item = FileItem;

    #[inline]
    fn next(&mut self) -> Option<FileItem> {
        self.0.next()
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.0.size_hint()
    }

    #[inline]
    fn count(self) -> usize {
        self.0.count()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct File {
    pub depot_file: String,
    pub client_file: String,
    pub path: String,
    non_exhaustive: (),
}

mod where_parser {
    use super::*;

    use super::super::parser::*;

    named!(file<&[u8], File>,
        do_parse!(
            depot_file: depot_file >>
            client_file: client_file >>
            path: path >>
            (
                File {
                    depot_file: depot_file.path.to_owned(),
                    client_file: client_file.path.to_owned(),
                    path: path.path.to_owned(),
                    non_exhaustive: (),
                }
            )
        )
    );

    fn file_to_item(f: File) -> FileItem {
        error::Item::Data(f)
    }

    fn error_to_item<T>(e: Error) -> error::Item<T> {
        error::Item::Message(error::Message::new(
            error::MessageLevel::Error,
            e.msg.to_owned(),
        ))
    }

    fn exit_to_item<T>(e: Exit) -> error::Item<T> {
        error::Item::Error(error::OperationError::new(e.code))
    }

    named!(item<&[u8], FileItem>,
        alt!(
            map!(file, file_to_item) |
            map!(error, error_to_item)
        )
    );

    named!(pub where_<&[u8], (Vec<FileItem>, FileItem)>,
        pair!(
            many0!(item),
            map!(exit, exit_to_item)
        )
    );
}