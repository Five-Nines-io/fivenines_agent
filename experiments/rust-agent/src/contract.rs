//! The server contract distinguishes three states per key (docker, wireguard,
//! openvpn, proxmox...):
//!   key absent  -> an older agent, the server changes nothing
//!   null        -> collection FAILED, the server must not prune
//!   []          -> a confirmed empty read, the server prunes everything
//! In Go, encoding/json maps a nil slice to null and omitempty turns [] into
//! an absent key (experiments/go-agent/contract_test.go). Here the three
//! states are three enum variants, and every match on them is exhaustive.

#[cfg(test)]
mod tests {
    use serde::{Serialize, Serializer};

    /// What one collector reports for one key.
    enum Reported<T> {
        Absent,
        Failed,
        Value(T),
    }

    impl<T> Reported<T> {
        fn is_absent(&self) -> bool {
            matches!(self, Reported::Absent)
        }
    }

    impl<T: Serialize> Serialize for Reported<T> {
        fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            match self {
                Reported::Value(v) => v.serialize(s),
                Reported::Failed => s.serialize_none(),
                Reported::Absent => unreachable!("skipped by skip_serializing_if"),
            }
        }
    }

    #[derive(Serialize)]
    struct WireGuard {
        #[serde(skip_serializing_if = "Reported::is_absent")]
        peers: Reported<Vec<String>>,
    }

    fn render(peers: Reported<Vec<String>>) -> String {
        serde_json::to_string(&WireGuard { peers }).unwrap()
    }

    #[test]
    fn three_states_are_three_values() {
        assert_eq!(render(Reported::Absent), "{}");
        assert_eq!(render(Reported::Failed), r#"{"peers":null}"#);
        assert_eq!(render(Reported::Value(vec![])), r#"{"peers":[]}"#);
    }

    #[test]
    fn there_is_no_nil_vec() {
        // An empty Vec is [], whatever way it was built.
        assert_eq!(serde_json::to_string(&Vec::<String>::new()).unwrap(), "[]");
        // null has to be written on purpose, through Option.
        assert_eq!(serde_json::to_string(&None::<Vec<String>>).unwrap(), "null");
    }

    #[test]
    fn the_omitempty_trap_exists_but_is_opt_in() {
        // serde's equivalent of omitempty drops [] exactly like Go's -- but it
        // has to be spelled out per field; nothing does it by default.
        #[derive(Serialize)]
        struct S {
            #[serde(skip_serializing_if = "Vec::is_empty")]
            peers: Vec<String>,
        }
        assert_eq!(serde_json::to_string(&S { peers: vec![] }).unwrap(), "{}");
    }
}
