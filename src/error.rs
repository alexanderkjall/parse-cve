#[derive(Debug)]
pub enum Error {
    Generic(String),
}

impl From<&str> for Error {
    fn from(err: &str) -> Error {
        Error::Generic(err.to_string())
    }
}

impl From<postgres::Error> for Error {
    fn from(err: postgres::Error) -> Error {
        Error::Generic(format!("{:?}", err))
    }
}

impl From<config::ConfigError> for Error {
    fn from(err: config::ConfigError) -> Error {
        Error::Generic(format!("{:?}", err))
    }
}

impl From<chrono::ParseError> for Error {
    fn from(err: chrono::ParseError) -> Error {
        Error::Generic(format!("{:?}", err))
    }
}

impl From<reqwest::Error> for Error {
    fn from(err: reqwest::Error) -> Error {
        Error::Generic(format!("{:?}", err))
    }
}

impl From<serde_json::Error> for Error {
    fn from(err: serde_json::Error) -> Error {
        Error::Generic(format!("{:?}", err))
    }
}

impl From<std::boxed::Box<dyn std::error::Error>> for Error {
    fn from(err: std::boxed::Box<dyn std::error::Error>) -> Error {
        Error::Generic(format!("{:?}", err))
    }
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Error {
        Error::Generic(format!("{:?}", err))
    }
}

pub type Result<T> = std::result::Result<T, Error>;
