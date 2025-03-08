use serde::{Deserialize, Serialize};

///
/// ScrapeRequestPayload
///
/// the request from frontend to server to start scraping
///
#[derive(Debug, Serialize, Deserialize)]
pub struct ScrapeRequestPayload {
    /// user id of the person logged in
    // FIXME: better userid impl
    pub userid: u32,
    /// which categories to add keywords to scrape from
    pub categories: Vec<ScrapeCategories>,
    /// platform to scrape
    pub platform: Platform,
}

///
/// ScrapeCategories
///
/// the categories by which keywords are added to the scraper
///
#[derive(Debug, Serialize, Deserialize)]
pub enum ScrapeCategories {
    /// memes from deepfake content
    Meme,
    /// nsfw deepfake content
    Nsfw,
    /// political deepfake content
    Political,
    /// all should alwasys be the last element
    /// if all is replaced as the last element
    /// update the Self::LEN calculation
    All,
}

impl ScrapeCategories {
    /// total number of categories
    pub const LEN: usize = ScrapeCategories::All as usize + 1;
}

impl From<usize> for ScrapeCategories {
    fn from(value: usize) -> Self {
        match value {
            0 => Self::Meme,
            1 => Self::Nsfw,
            2 => Self::Political,
            3 => Self::All,
            _ => unreachable!("no no shudnt come here. check ur bounds"),
        }
    }
}

///
/// Platform
///
/// the platform which is being scraped
///
#[derive(Debug, Serialize, Deserialize)]
pub enum Platform {
    /// x.com
    X,
    /// facebook.com
    Facebook,
    /// this should never be used unless
    /// if we plan to support multiple platforms
    _All,
}

impl Platform {
    /// total num
    pub const LEN: usize = Platform::_All as usize;
}

impl From<usize> for Platform {
    fn from(value: usize) -> Self {
        match value {
            0 => Platform::X,
            1 => Platform::Facebook,
            _ => unreachable!("no this shudnt happen."),
        }
    }
}
