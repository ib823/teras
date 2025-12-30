//! HTTP fetcher for threat feeds.
//!
//! Handles downloading feeds with proper error handling and retries.

use crate::feed::FeedSource;
use std::time::Duration;
use teras_core::{TerasError, TerasResult};

/// HTTP fetcher for downloading threat feeds.
pub struct FeedFetcher {
    client: reqwest::Client,
    #[allow(dead_code)]
    timeout: Duration,
    max_retries: u32,
}

impl FeedFetcher {
    /// Create a new fetcher with default settings.
    ///
    /// # Panics
    ///
    /// Panics if HTTP client cannot be created.
    #[must_use]
    pub fn new() -> Self {
        Self::with_timeout(Duration::from_secs(30))
    }

    /// Create a fetcher with custom timeout.
    ///
    /// # Panics
    ///
    /// Panics if HTTP client cannot be created.
    #[must_use]
    pub fn with_timeout(timeout: Duration) -> Self {
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .user_agent("TERAS-Suap/0.1.0")
            .build()
            .expect("Failed to create HTTP client");

        Self {
            client,
            timeout,
            max_retries: 3,
        }
    }

    /// Set maximum retry attempts.
    #[must_use]
    pub const fn with_retries(mut self, retries: u32) -> Self {
        self.max_retries = retries;
        self
    }

    /// Fetch a feed source.
    ///
    /// # Errors
    ///
    /// Returns error if fetch fails after all retries.
    pub async fn fetch(&self, source: &dyn FeedSource) -> TerasResult<Vec<u8>> {
        let url = source.url();
        let headers = source.headers();
        let source_id = source.id().to_string();

        let mut last_error = None;

        for attempt in 0..=self.max_retries {
            if attempt > 0 {
                // Exponential backoff
                let delay = Duration::from_millis(100 * 2u64.pow(attempt - 1));
                tokio::time::sleep(delay).await;
            }

            match self.fetch_once(url, &headers).await {
                Ok(data) => return Ok(data),
                Err(e) => {
                    last_error = Some(e);
                }
            }
        }

        Err(
            last_error.unwrap_or_else(|| TerasError::ThreatFeedFetchFailed {
                source: source_id,
                reason: "Unknown error".to_string(),
            }),
        )
    }

    async fn fetch_once(&self, url: &str, headers: &[(String, String)]) -> TerasResult<Vec<u8>> {
        let mut request = self.client.get(url);

        for (key, value) in headers {
            request = request.header(key, value);
        }

        let response = request
            .send()
            .await
            .map_err(|e| TerasError::ThreatFeedFetchFailed {
                source: url.to_string(),
                reason: e.to_string(),
            })?;

        if !response.status().is_success() {
            return Err(TerasError::ThreatFeedFetchFailed {
                source: url.to_string(),
                reason: format!("HTTP {}", response.status()),
            });
        }

        response
            .bytes()
            .await
            .map(|b| b.to_vec())
            .map_err(|e| TerasError::ThreatFeedFetchFailed {
                source: url.to_string(),
                reason: e.to_string(),
            })
    }
}

impl Default for FeedFetcher {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fetcher_creation() {
        let fetcher = FeedFetcher::new();
        assert_eq!(fetcher.max_retries, 3);
    }

    #[test]
    fn test_fetcher_with_retries() {
        let fetcher = FeedFetcher::new().with_retries(5);
        assert_eq!(fetcher.max_retries, 5);
    }

    #[test]
    fn test_fetcher_with_timeout() {
        let fetcher = FeedFetcher::with_timeout(Duration::from_secs(60));
        assert_eq!(fetcher.timeout, Duration::from_secs(60));
    }
}
