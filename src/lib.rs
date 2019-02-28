#[macro_use]
extern crate failure;
#[macro_use]
extern crate lazy_static;
extern crate yara_sys;
#[cfg(test)]
extern crate tempdir;

mod compiler;
mod internals;
mod matches;
mod rules;
mod string;

pub mod errors;

pub use compiler::Compiler;
pub use errors::*;
pub use matches::Match;
pub use rules::*;
pub use string::YrString;

/// Yara library.
/// Necessary to use the features of this crate.
///
/// # Implementation notes
///
/// libyara asks to call `yr_initialize` before use the library.
/// Because yara keeps a count of how many times `yr_initialize` is used,
/// it doesn't matter if this struct is constructed multiple times.
pub struct Yara {
    _secret: (),
}

impl Yara {
    /// Create and initialize the library.
    pub fn create() -> Result<Yara, YaraError> {
        internals::initialize().map(|()| Yara { _secret: () })
    }

    /// Create a new compiler.
    // TODO Check if method is thread safe, and if "mut" is needed.
    pub fn new_compiler<'a>(&'a mut self) -> Result<Compiler<'a>, YaraError> {
        Compiler::<'a>::create()
    }

    /// Load rules from a pre-compiled rules file.
    // TODO Check if method is thread safe, and if "mut" is needed.
    // TODO Take AsRef<Path> ?
    pub fn load_rules<'a>(&'a mut self, filename: &str) -> Result<Rules<'a>, YaraError> {
        internals::rules_load(filename).map(Rules::from)
    }
}

/// Finalize the Yara library
impl Drop for Yara {
    fn drop(&mut self) {
        internals::finalize().expect("Expect correct Yara finalization");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::fs::File;
    use std::io::Write;
    use std::path::PathBuf;
    use tempdir::TempDir;

    static FILE_1_CONTENT: &[u8; 5] = b"Test1";

    fn root_folder() -> TempDir {
        let tmp_dir = TempDir::new("test").unwrap();
        tmp_dir
    }

    fn file_1(root: &TempDir) -> PathBuf {
        let root_folder_1 = root.path().join("folder_1");

        fs::create_dir_all(&root_folder_1).expect(&format!(
            "Failed to create dir {:#?}",
            &root_folder_1.to_str().unwrap()
        ));

        let file_11 = root_folder_1.join("test_11.txt");

        let mut f = File::create(&file_11).unwrap();
        f.write(FILE_1_CONTENT).unwrap();

        file_11
    }

    #[test]
    fn test_scan_file_with_non_matching_rule() {
        let root = root_folder();
        let file_1 = file_1(&root);

        let mut yara = Yara::create().unwrap();
        let mut compiler = yara.new_compiler().unwrap();

        match compiler.add_rules_str_with_namespace(
            "rule not_match {
          strings:
            $text = \"RANDOM TEXT\" nocase
          condition:
            $text
        }",
            "yara-scan",
        ) {
            Ok(_) => {}
            Err(e) => assert!(false),
        };

        let mut rules = compiler
            .compile_rules()
            .expect("Should have compiled rules");

        let scan_results = rules.scan_file(file_1, 0);
        assert!(scan_results.is_ok());
        let scan_results = scan_results.unwrap();
        assert_eq!(scan_results.len(), 0);
    }

    #[test]
    fn test_scan_file_with_matching_rule() {
        let root = root_folder();
        let file_1 = file_1(&root);

        let mut yara = Yara::create().unwrap();
        let mut compiler = yara.new_compiler().unwrap();

        match compiler.add_rules_str_with_namespace(
            "rule matches_the_test_file {
            strings:
            $text = \"Test1\" nocase
  condition:
    $text
}",
            "yara-scan",
        ) {
            Ok(_) => {}
            Err(e) => assert!(false),
        };

        let mut rules = compiler
            .compile_rules()
            .expect("Should have compiled rules");

        let scan_results = rules.scan_file(file_1, 0);

        println!("{:#?}", scan_results);

        assert!(scan_results.is_ok());
        let scan_results = scan_results.unwrap();
        assert_eq!(scan_results.len(), 1);
        let matching_rule = &scan_results[0];
        assert_eq!(matching_rule.identifier, "matches_the_test_file");
    }
}
