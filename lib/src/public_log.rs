use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;

#[derive(Debug)]
pub enum PublicLogError {
    Io(std::io::Error),
    Serialization(serde_json::Error),
    IndexOutOfBounds(usize),
    EmptyLog,
}

impl std::fmt::Display for PublicLogError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PublicLogError::Io(e) => write!(f, "IO error: {}", e),
            PublicLogError::Serialization(e) => write!(f, "Serialization error: {}", e),
            PublicLogError::IndexOutOfBounds(idx) => write!(f, "Index out of bounds: {}", idx),
            PublicLogError::EmptyLog => write!(f, "Log is empty"),
        }
    }
}

impl std::error::Error for PublicLogError {}

impl From<std::io::Error> for PublicLogError {
    fn from(error: std::io::Error) -> Self {
        PublicLogError::Io(error)
    }
}

impl From<serde_json::Error> for PublicLogError {
    fn from(error: serde_json::Error) -> Self {
        PublicLogError::Serialization(error)
    }
}

#[derive(Debug)]
pub struct PublicLog {
    file_path: PathBuf,
}

impl PublicLog {
    pub fn new() -> Self {
        Self {
            file_path: PathBuf::from("public_log.jsonl"),
        }
    }

    pub fn post<T>(&self, item: &T) -> Result<(), PublicLogError>
    where
        T: Serialize,
    {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.file_path)?;

        let json_line = serde_json::to_string(item)?;
        writeln!(file, "{}", json_line)?;
        file.flush()?;

        Ok(())
    }

    pub fn last<T>(&self) -> Result<T, PublicLogError>
    where
        T: for<'de> Deserialize<'de>,
    {
        match File::open(&self.file_path) {
            Ok(file) => {
                let reader = BufReader::new(file);
                let lines: Vec<String> = reader
                    .lines()
                    .collect::<Result<Vec<_>, _>>()?
                    .into_iter()
                    .filter(|line| !line.trim().is_empty())
                    .collect();

                let last_line = lines.last().ok_or(PublicLogError::EmptyLog)?;
                let item: T = serde_json::from_str(last_line)?;

                Ok(item)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(PublicLogError::EmptyLog),
            Err(e) => Err(PublicLogError::Io(e)),
        }
    }

    pub fn get<T>(&self, index: usize) -> Result<T, PublicLogError>
    where
        T: for<'de> Deserialize<'de>,
    {
        let file = File::open(&self.file_path)?;
        let reader = BufReader::new(file);
        let lines: Vec<String> = reader
            .lines()
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .filter(|line| !line.trim().is_empty())
            .collect();

        let line = lines.get(index).ok_or(PublicLogError::IndexOutOfBounds(index))?;
        let item: T = serde_json::from_str(line)?;

        Ok(item)
    }

    pub fn len(&self) -> Result<usize, PublicLogError> {
        match File::open(&self.file_path) {
            Ok(file) => {
                let reader = BufReader::new(file);
                let count = reader
                    .lines()
                    .collect::<Result<Vec<_>, _>>()?
                    .into_iter()
                    .filter(|line| !line.trim().is_empty())
                    .count();
                Ok(count)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(0),
            Err(e) => Err(PublicLogError::Io(e)),
        }
    }

    pub fn is_empty(&self) -> Result<bool, PublicLogError> {
        Ok(self.len()? == 0)
    }
}

impl Default for PublicLog {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};
    use std::fs;

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct TestMessage {
        content: String,
        timestamp: u64,
    }

    fn create_test_log() -> PublicLog {
        use std::time::{SystemTime, UNIX_EPOCH};
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let test_file = format!("/tmp/test_public_log_{}_{}.jsonl", std::process::id(), timestamp);
        PublicLog {
            file_path: PathBuf::from(test_file),
        }
    }

    fn cleanup_test_log(log: &PublicLog) {
        let _ = fs::remove_file(&log.file_path);
    }

    #[test]
    fn test_post_and_get() {
        let log = create_test_log();

        let msg1 = TestMessage {
            content: "Hello".to_string(),
            timestamp: 1000,
        };
        let msg2 = TestMessage {
            content: "World".to_string(),
            timestamp: 2000,
        };

        log.post(&msg1).unwrap();
        log.post(&msg2).unwrap();

        let retrieved_msg1: TestMessage = log.get(0).unwrap();
        let retrieved_msg2: TestMessage = log.get(1).unwrap();

        assert_eq!(retrieved_msg1, msg1);
        assert_eq!(retrieved_msg2, msg2);

        cleanup_test_log(&log);
    }

    #[test]
    fn test_last() {
        let log = create_test_log();

        let msg1 = TestMessage {
            content: "First".to_string(),
            timestamp: 1000,
        };
        let msg2 = TestMessage {
            content: "Last".to_string(),
            timestamp: 2000,
        };

        log.post(&msg1).unwrap();
        log.post(&msg2).unwrap();

        let last_msg: TestMessage = log.last().unwrap();
        assert_eq!(last_msg, msg2);

        cleanup_test_log(&log);
    }

    #[test]
    fn test_empty_log() {
        let log = create_test_log();

        let result: Result<TestMessage, _> = log.last();
        assert!(matches!(result, Err(PublicLogError::EmptyLog)));

        assert!(log.is_empty().unwrap());
        assert_eq!(log.len().unwrap(), 0);

        cleanup_test_log(&log);
    }

    #[test]
    fn test_index_out_of_bounds() {
        let log = create_test_log();

        let msg = TestMessage {
            content: "Only one".to_string(),
            timestamp: 1000,
        };

        log.post(&msg).unwrap();

        let result: Result<TestMessage, _> = log.get(1);
        assert!(matches!(result, Err(PublicLogError::IndexOutOfBounds(1))));

        cleanup_test_log(&log);
    }
}