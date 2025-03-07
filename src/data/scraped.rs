use serde::{Deserialize, Serialize};

///
/// ScrapedData
///
/// Sent by the webscraper to the server
/// via /scraped-data endpoint
///
#[derive(Debug, Serialize, Deserialize)]
pub struct ScrapedData {
    data: Vec<MatchedLink>,
}

///
/// MatchedLink
///
/// Each link the scraper matches with keywords
///
#[derive(Debug, Serialize, Deserialize)]
pub struct MatchedLink {
    /// user name of the user which posted the deepfake
    user: String,
    /// the platform at which the deepfake was posted to
    platform: String,
    /// the link of the post which is flagged as the deepfake
    link: String,
}

///
/// ForwardData
///
/// Data sent by the server to the ai module
///
#[derive(Debug, Serialize, Deserialize)]
pub struct ForwardData {
    data: Vec<SanitizedLink>,
}

///
/// SanitizedData
///
/// Data from MatchedLink sanitized and processed
/// provides relevant context for the ai module and server communication
///
#[derive(Debug, Serialize, Deserialize)]
pub struct SanitizedLink {
    /// the unique user identifier
    // FIXME: implement better user identification
    userid: u32,
    /// the unique link identifier
    // FIXME: implement better user identification
    linkid: u32,
    /// the link of the post flagged as deepfake
    link: String,
}
