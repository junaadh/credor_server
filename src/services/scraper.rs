use std::{num::NonZero, sync::Arc};

use governor::{DefaultDirectRateLimiter, Quota, RateLimiter};
use serde::{Deserialize, Serialize};
use tracing::{info, trace};

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize,
)]
#[serde(rename_all = "lowercase")]
pub enum ScrapeTarget {
    BlueSky,
}

pub type Limiter = Arc<DefaultDirectRateLimiter>;

pub trait Scraper: Send + Sync {
    type AuthPayload: Serialize;
    type Output: Serialize + for<'de> Deserialize<'de> + std::fmt::Debug;
    const LIMIT: u32;

    fn make_limiter() -> Limiter {
        Arc::new(RateLimiter::direct(Quota::per_minute(
            NonZero::new(Self::LIMIT).unwrap(),
        )))
    }

    fn limiter(&self) -> Limiter;

    fn auth<'a>(
        &'a mut self,
        payload: &'a Self::AuthPayload,
    ) -> impl Future<Output = anyhow::Result<()>> + 'a;

    fn fetch<'a>(
        &'a self,
        cursor: String,
        limit: String,
        search_query: String,
    ) -> impl Future<Output = anyhow::Result<serde_json::Value>> + 'a;

    fn scrape<'a>(
        &'a self,
        search_query: String,
    ) -> impl Future<Output = anyhow::Result<Option<Self::Output>>> + 'a {
        async move {
            let mut result = Vec::new();
            let mut cursor = 0;
            for _ in 0..6 {
                let value = self
                    .fetch(
                        format!("{cursor}"),
                        String::from("20"),
                        search_query.clone(),
                    )
                    .await?;

                // if let serde_json::Value::Object(obj) = &value
                //     && obj.is_empty()
                // {
                //     return Ok(None);
                // }

                let is_hard_limit = value
                    .get("cursor")
                    .map(|x| x.as_u64().unwrap_or_default())
                    .unwrap_or_default();

                if let Some(serde_json::Value::Array(posts)) =
                    value.get("posts")
                {
                    result.extend_from_slice(posts);
                }

                // result
                //     .extend_from_slice(value.get("posts").cloned().as_slice());

                if is_hard_limit > 100 || is_hard_limit > 400 {
                    break;
                } else {
                    cursor += value
                        .get("cursor")
                        .map(|i| i.as_u64().unwrap_or_default())
                        .unwrap_or_default();
                }
            }

            let value = serde_json::json!({ "cursor": "0", "posts": result });

            // info!("{value:#?}");
            let s = serde_json::from_value::<Self::Output>(value)?;
            trace!("{s:#?}");
            Ok(Some(s))
        }
    }
}
