//! The board of the road at a public MQTT broker: `pod_wormhole`'s board of
//! retained messages ([`pod_wormhole::mqtt::Board`]), each call on a
//! connection of its own, closed before the next, at a broker of
//! `pod-services`' kind `mqtt-broker` (T-737's, through
//! [`crate::code::brokers`]). Both ends of a pair take the first broker of
//! that list, so that a note put by one is where the other takes it.

use std::time::Duration;

use pod_wormhole::mqtt;

use super::board::{Board, Posting};

/// How long a take waits for the topic's retained message after its
/// subscription: a broker sends it at once, so a short wait is a topic
/// that keeps none.
pub const TAKE_WAIT: Duration = Duration::from_secs(3);

/// A board at one MQTT broker.
pub struct MqttBoard {
    board: mqtt::Board,
    name: String,
}

impl MqttBoard {
    /// The board at `point`, each connection made with `config` (podssh's
    /// way out and trust, as `crate::code::config` makes them).
    pub fn new(point: mqtt::Point, config: pod_wormhole::Config) -> MqttBoard {
        let board = mqtt::Board::new(point, config);
        MqttBoard { name: board.shown(), board }
    }

    /// The board at the first of `points`; `None` with none.
    pub fn first(points: Vec<mqtt::Point>, config: pod_wormhole::Config) -> Option<MqttBoard> {
        points.into_iter().next().map(|point| MqttBoard::new(point, config))
    }
}

impl Board for MqttBoard {
    fn name(&self) -> &str {
        &self.name
    }

    fn most(&self) -> usize {
        mqtt::PAYLOAD_MOST
    }

    fn put<'a>(&'a self, topic: &'a str, payload: Vec<u8>) -> Posting<'a, ()> {
        Box::pin(async move { self.board.put(topic, &payload).await.map_err(|e| e.to_string()) })
    }

    fn take<'a>(&'a self, topic: &'a str) -> Posting<'a, Option<Vec<u8>>> {
        Box::pin(async move { self.board.take(topic, TAKE_WAIT).await.map_err(|e| e.to_string()) })
    }

    fn clear<'a>(&'a self, topic: &'a str) -> Posting<'a, ()> {
        Box::pin(async move { self.board.clear(topic).await.map_err(|e| e.to_string()) })
    }
}

#[cfg(test)]
mod tests {
    use super::super::keys::{Keys, Kind, LinkId, Way, OVERHEAD};
    use crate::session::OsEntropy;
    use pod_wormhole::mqtt::board::{check_payload, check_topic};

    /// Each topic of the road is one that the board takes (letters and
    /// digits, 42 at most), and a note of the largest URL and token that a
    /// host gives fits a message.
    #[test]
    fn the_road_s_topics_and_notes_fit_the_mqtt_board() {
        let keys = Keys::from_bytes([7; 32]);
        let (up, down) = (keys.topic(Way::Up, &LinkId([1; 16]), 0), keys.topic(Way::Down, &LinkId([9; 16]), 1 << 40));
        for topic in [keys.door(), up, down] {
            assert!(check_topic(&topic).is_ok(), "{topic}");
        }
        let url = format!("https://{}/{}", "h".repeat(253), "p".repeat(2000));
        let note = serde_json::json!({ "h": "h".repeat(253), "u": url, "t": "t".repeat(256) }).to_string();
        let sealed = keys.seal(Kind::Note, Way::Up, &LinkId([1; 16]), 0, note.as_bytes(), &mut OsEntropy).unwrap();
        assert_eq!(sealed.len(), note.len() + OVERHEAD);
        assert!(check_payload(&sealed).is_ok());
        assert!(sealed.len() < super::mqtt::PAYLOAD_MOST);
    }
}
