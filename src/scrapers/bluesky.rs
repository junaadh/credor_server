use models::FlattenedThreadResponse;
use std::{env, ops::Deref};
use tracing::trace;

use crate::{Limiter, Scraper};

#[derive(Debug)]
pub struct BlueskyScraper {
    bearer_token: Option<String>,
    limiter: Limiter,
}

impl BlueskyScraper {
    pub fn new() -> Self {
        Self {
            bearer_token: None,
            limiter: <Self as Scraper>::make_limiter(),
        }
    }

    pub fn flatten_thread(
        thread: &serde_json::Value,
    ) -> Vec<serde_json::Value> {
        let mut out = vec![];
        if let Some(replies) = thread.get("replies").and_then(|r| r.as_array())
        {
            for reply in replies {
                out.push(reply.clone());
                out.extend(Self::flatten_thread(reply));
            }
        }
        out
    }

    fn construct_thread(json: &serde_json::Value) -> serde_json::Value {
        let post = &json["post"];
        let flattened_replies = Self::flatten_thread(json);

        serde_json::json!({ "post": post, "flattened_replies": flattened_replies })
    }
}

impl Deref for BlueskyScraper {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        if let Some(auth) = self.bearer_token.as_ref() {
            auth
        } else {
            // assumes deref happens only after the scraper had been authenticated
            // not safe
            ""
        }
    }
}

// make clippy happy
impl Default for BlueskyScraper {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(serde::Serialize)]
pub struct BlueskyAuthPayload {
    identifier: String,
    password: String,
}

impl BlueskyAuthPayload {
    pub fn new() -> anyhow::Result<Self> {
        let identifier = env::var("BOT_ID")?;
        let password = env::var("BOT_PASSWORD")?;

        Ok(Self {
            identifier,
            password,
        })
    }
}

// impl<'a> Scraper<'a> for BlueskyScraper {
impl Scraper for BlueskyScraper {
    type AuthPayload = BlueskyAuthPayload;
    type Output = FlattenedThreadResponse;
    /// 3000 reqs / 5 mins so 3000 / 5 = 600 but conservitively 500
    const LIMIT: u32 = 500;

    fn limiter(&self) -> Limiter {
        self.limiter.clone()
    }

    fn auth<'a>(
        &'a mut self,
        payload: &'a Self::AuthPayload,
    ) -> impl Future<Output = anyhow::Result<()>> {
        async move {
            if self.bearer_token.is_some() {
                return Ok(());
            }

            let res = reqwest::Client::new()
                .post(
                    "https://bsky.social/xrpc/com.atproto.server.createSession",
                )
                .header("Content-Type", "application/json")
                .body(serde_json::to_string(payload)?)
                .send()
                .await?;

            if !res.status().is_success() {
                anyhow::bail!(
                    "bluesky scraper auth return {:?}",
                    res.text().await
                );
            }

            let json: serde_json::Value = res.json().await?;
            let access_jwt = json["accessJwt"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("accessJwt missing"))?;

            self.bearer_token = Some(access_jwt.to_string());
            Ok(())
        }
    }

    fn fetch<'a>(
        &'a self,
        cursor: String,
        limit: String,
        search_query: String,
    ) -> impl Future<Output = anyhow::Result<serde_json::Value>> + 'a {
        let limiter = self.limiter();
        async move {
            limiter.until_ready().await;

            let res = reqwest::Client::new()
                .get("https://bsky.social/xrpc/app.bsky.feed.searchPosts")
                .query(&[
                    ("q", search_query),
                    ("limit", limit),
                    ("cursor", cursor),
                ])
                .bearer_auth(&**self)
                .send()
                .await?;

            if !res.status().is_success() {
                anyhow::bail!(
                    "bluesky scraper auth return {:?}",
                    res.text().await
                );
            }

            let json: serde_json::Value = res.json().await?;
            let posts = json["posts"]
                .as_array()
                .ok_or_else(|| anyhow::anyhow!("no posts with the keywords"))?;

            let mut all = vec![];
            let mut tasks = vec![];

            for post in posts {
                let post_view = post;

                // skip without pictures
                match post_view.get("embed") {
                    Some(serde_json::Value::Object(map)) if !map.is_empty() => {
                    }
                    _ => continue,
                }

                let reply_count = post["replyCount"].as_u64().unwrap_or(0);
                if reply_count == 0 {
                    all.push(serde_json::json!({ "post": post_view, "flattened_replies": [] }));
                    continue;
                }

                let uri =
                    post_view["uri"].as_str().unwrap_or_default().to_string();
                let bearer = self
                    .bearer_token
                    .clone()
                    .ok_or_else(|| anyhow::anyhow!("not authed"))?;
                let limiter_inner = limiter.clone();

                tasks.push(tokio::spawn(async move {
                    limiter_inner.until_ready().await;
                    let res = reqwest::Client::new()
                    .get("https://bsky.social/xrpc/app.bsky.feed.getPostThread")
                    .query(&[("uri", &uri)])
                    .bearer_auth(bearer)
                    .send()
                    .await?;

                    let json: serde_json::Value = res.json().await?;

                    Ok::<_, anyhow::Error>(Self::construct_thread(
                        &json["thread"],
                    ))
                }));
            }

            let results = futures::future::join_all(tasks).await;

            for r in results {
                let r = r??;
                trace!("{r:#?}");
                all.push(r);
            }

            if all.is_empty() {
                return Ok(serde_json::json!({}));
            }

            let cursor = &json["cursor"];

            Ok(serde_json::json!({ "cursor": cursor, "posts": all }))
        }
    }
}

pub mod models {
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Serialize, Deserialize)]
    pub struct FlattenedThreadResponse {
        pub cursor: String,
        // #[serde(default)]
        pub posts: Vec<FlattenedPost>,
    }

    impl FlattenedThreadResponse {
        pub fn new(data: Vec<(u32, Vec<&str>)>) -> Self {
            Self {
                cursor: "0".to_string(),
                posts: data
                    .into_iter()
                    .map(|(r, i)| FlattenedPost::new(r, i))
                    .collect(),
            }
        }
    }

    #[derive(Debug, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct FlattenedPost {
        pub post: PostView,
        // #[serde(default)]
        // pub flattened_replies: Vec<PostView>,
    }

    impl FlattenedPost {
        pub fn new(reply: u32, imgs: Vec<&str>) -> Self {
            // Self {
            // post: PostView {
            //     author: Author { handle: "", display_name: (), avatar: () }
            //     embed: Some(Embed::new(imgs)),
            //     reply_count: Some(reply),
            // },
            // }
            todo!()
        }
    }

    #[derive(Debug, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct ThreadViewPost {
        pub post: PostView,
        #[serde(default)]
        pub replies: Vec<ThreadViewPost>,
    }

    #[derive(Debug, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct PostView {
        // pub uri: String,
        pub author: Author,
        #[serde(default)]
        pub embed: Option<Embed>,
        pub reply_count: Option<u32>,
    }

    #[derive(Debug, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct Author {
        pub handle: String,
        pub display_name: Option<String>,
        pub avatar: Option<String>,
    }

    #[derive(Debug, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct Embed {
        #[serde(default)]
        pub images: Vec<ImageView>,
        pub external: Option<External>,
    }

    impl Embed {
        pub fn new(_imgs: Vec<&str>) -> Self {
            todo!()
        }
    }

    #[derive(Debug, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct External {
        pub thumb: Option<String>,
    }

    #[derive(Debug, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct ImageView {
        pub fullsize: Option<String>,
    }

    impl ImageView {
        pub fn new(imgs: &str) -> Self {
            Self {
                fullsize: Some(imgs.to_string()),
            }
        }
    }
}

// #[tokio::test]
// async fn test_bluesky_auth() {
//     use dotenv::dotenv;

//     dotenv().ok();

//     let payload = BlueskyAuthPayload::new().unwrap();
//     let mut scraper = BlueskyScraper::new();

//     scraper.auth(&payload).await.unwrap();

//     // let result = scraper.fetch().await;
//     let result = scraper.scrape("kim kardashian".to_string()).await;
//     match result {
//         Ok(v) => {
//             println!("Success! : {v:#?}");
//         }
//         Err(e) => {
//             eprintln!("Auth failed: {e:?}");
//             panic!();
//         }
//     }
// }
