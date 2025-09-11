use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

pub mod json_pod_converter;
pub mod membership;
pub mod model;
pub mod utils;

// Re-export the derive macro for convenience
pub use pod_derive::IntoTypedValue;

#[derive(Debug, Serialize, Deserialize)]
struct IndexedItem<T> {
    index: usize,
    data: T,
}

pub struct FileState {
    file_path: String,
}

#[derive(Debug)]
pub enum FileStateError {
    IoError(std::io::Error),
    SerializationError(serde_json::Error),
    IndexOutOfBounds,
    EmptyFile,
    IndexMismatch { expected: usize, found: usize },
}

impl From<std::io::Error> for FileStateError {
    fn from(error: std::io::Error) -> Self {
        FileStateError::IoError(error)
    }
}

impl From<serde_json::Error> for FileStateError {
    fn from(error: serde_json::Error) -> Self {
        FileStateError::SerializationError(error)
    }
}

impl FileState {
    pub fn new(file_path: &str) -> Self {
        FileState {
            file_path: file_path.to_string(),
        }
    }

    fn get_next_index(&self) -> Result<usize, FileStateError> {
        if !Path::new(&self.file_path).exists() {
            return Ok(0);
        }

        let file = File::open(&self.file_path)?;
        let reader = BufReader::new(file);

        let mut count = 0;
        for _ in reader.lines() {
            count += 1;
        }

        Ok(count)
    }

    pub fn post<T: Serialize>(&self, item: &T) -> Result<(), FileStateError> {
        let next_index = self.get_next_index()?;
        let indexed_item = IndexedItem {
            index: next_index,
            data: item,
        };

        let json_line = serde_json::to_string(&indexed_item)?;

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.file_path)?;

        writeln!(file, "{}", json_line)?;
        Ok(())
    }

    pub fn fetch<T: for<'de> Deserialize<'de>>(&self, index: usize) -> Result<T, FileStateError> {
        if !Path::new(&self.file_path).exists() {
            return Err(FileStateError::IndexOutOfBounds);
        }

        let file = File::open(&self.file_path)?;
        let reader = BufReader::new(file);

        for (line_num, line) in reader.lines().enumerate() {
            if line_num == index {
                let line = line?;
                let indexed_item: IndexedItem<T> = serde_json::from_str(&line)?;

                if indexed_item.index != index {
                    return Err(FileStateError::IndexMismatch {
                        expected: index,
                        found: indexed_item.index,
                    });
                }

                return Ok(indexed_item.data);
            }
        }

        Err(FileStateError::IndexOutOfBounds)
    }

    pub fn last<T: for<'de> Deserialize<'de>>(&self) -> Result<T, FileStateError> {
        if !Path::new(&self.file_path).exists() {
            return Err(FileStateError::EmptyFile);
        }

        let file = File::open(&self.file_path)?;
        let reader = BufReader::new(file);

        let mut last_line = None;
        let mut expected_index = 0;

        for (line_num, line) in reader.lines().enumerate() {
            last_line = Some(line?);
            expected_index = line_num;
        }

        match last_line {
            Some(line) => {
                let indexed_item: IndexedItem<T> = serde_json::from_str(&line)?;

                if indexed_item.index != expected_index {
                    return Err(FileStateError::IndexMismatch {
                        expected: expected_index,
                        found: indexed_item.index,
                    });
                }

                Ok(indexed_item.data)
            }
            None => Err(FileStateError::EmptyFile),
        }
    }
}
