use thiserror::Error;

#[derive(Debug, Error)]
#[error("{message}")]
pub struct HoundDogError {
    pub message: String,
    pub sentry: bool,
}
