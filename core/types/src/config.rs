use config::{Config, ConfigError};
use serde::Deserialize;

pub trait ConfigReader<'de, T: Deserialize<'de>> {
    fn read_config() -> Result<T, ConfigError> {
        let config = Config::builder()
            .add_source(config::Environment::default().separator("__"))
            .build()?;

        config.try_deserialize::<T>()
    }
}

impl<'de, T: Deserialize<'de>> ConfigReader<'de, T> for T {}
