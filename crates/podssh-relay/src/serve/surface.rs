//! The role's public routes as one table (#225, T-767): each path family,
//! its method, and whether it is a document that `--cover` moves to the
//! local socket. The router reads this table before it matches a handler, so
//! a path that is not in it reaches no handler and gets the site's 404 (or
//! the role's, without a cover). The test below is the allow-list: a route
//! added here, or a handler that the table does not name, changes the list
//! and fails until the list is reviewed. A new handler without an entry is
//! unreachable, which is the fail-closed half of the same rule.

use super::{http_road, layer, leg, mailbox, meet, probe, reverse};

/// Whether `path` is DERP's, where the feature that serves it is built.
#[cfg(feature = "derp")]
fn derp_serves(path: &str) -> bool {
    super::derp::serves(path)
}

/// No DERP without its feature.
#[cfg(not(feature = "derp"))]
fn derp_serves(_path: &str) -> bool {
    false
}

/// Where a request arrived: the public listener, or the owner's socket.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Surface {
    Public,
    Local,
}

/// Whether a route stays on the public listener, or moves to the local
/// socket under a cover.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reach {
    /// Served to anyone: the mint is the one such route (SURF-2).
    Open,
    /// Served to a client that proves a token or a key (SURF-1).
    Token,
    /// A document or a probe, which `--cover` moves to the local socket.
    Local,
}

/// The method a route takes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    Get,
    Post,
    Any,
}

/// What a route is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Id {
    Mint,
    Health,
    Relays,
    Trace,
    Spec,
    Probe,
    Delegate,
    HttpRoad,
    Connect,
    Layer,
    Mailbox,
    Leg,
    Reverse,
    Derp,
    Meet,
}

/// How a route recognizes its path.
#[derive(Clone, Copy, Debug)]
pub enum Pattern {
    Exact(&'static str),
    Prefix(&'static str),
    Fn(fn(&str) -> bool),
}

impl Method {
    /// The method as a request line writes it; `Any` writes GET, which each
    /// row of that method always takes.
    pub fn as_str(self) -> &'static str {
        match self {
            Method::Get => "GET",
            Method::Post => "POST",
            Method::Any => "GET",
        }
    }
}

impl Pattern {
    fn holds(self, path: &str) -> bool {
        match self {
            Pattern::Exact(text) => path == text,
            Pattern::Prefix(text) => path.starts_with(text),
            Pattern::Fn(check) => check(path),
        }
    }
}

/// One route of the role.
#[derive(Clone, Copy, Debug)]
pub struct Route {
    pub method: Method,
    pub id: Id,
    pub reach: Reach,
    matches: Pattern,
    /// A path that this row matches, for a test that sends one request to
    /// every row: a new row must state one, and the live test reaches it.
    pub example: &'static str,
}

/// Whether `path`, with no query, is a route's.
pub fn classify(method: &str, path: &str) -> Option<&'static Route> {
    ROUTES.iter().find(|route| route.takes(method) && route.matches.holds(path))
}

impl Route {
    fn takes(&self, method: &str) -> bool {
        match self.method {
            Method::Get => method == "GET",
            Method::Post => method == "POST",
            Method::Any => true,
        }
    }
}

/// Every route of the role, and the reach of each. The test below holds this
/// list to the router: a route that is not here is not served, and a handler
/// added without its row fails the test.
pub const ROUTES: &[Route] = &[
    // The one public endpoint: a token of the forward road (SURF-2). Under a
    // cover it takes a POST with a body alone.
    Route {
        method: Method::Any,
        id: Id::Mint,
        reach: Reach::Open,
        matches: Pattern::Exact("/v1/mint"),
        example: "/v1/mint",
    },
    // The documents and the probes (SURF-1): moved to the local socket.
    Route {
        method: Method::Get,
        id: Id::Health,
        reach: Reach::Local,
        matches: Pattern::Exact("/health"),
        example: "/health",
    },
    Route {
        method: Method::Get,
        id: Id::Relays,
        reach: Reach::Local,
        matches: Pattern::Exact("/relays.json"),
        example: "/relays.json",
    },
    Route {
        method: Method::Get,
        id: Id::Trace,
        reach: Reach::Local,
        matches: Pattern::Exact("/trace"),
        example: "/trace",
    },
    Route {
        method: Method::Get,
        id: Id::Spec,
        reach: Reach::Local,
        matches: Pattern::Exact("/llms-full.txt"),
        example: "/llms-full.txt",
    },
    Route {
        method: Method::Any,
        id: Id::Probe,
        reach: Reach::Local,
        matches: Pattern::Fn(probe::serves),
        example: "/v1/probe/drip",
    },
    // The application-layer credential of a cover name (T-765): a token
    // proves the client before it is issued.
    Route {
        method: Method::Any,
        id: Id::Delegate,
        reach: Reach::Token,
        matches: Pattern::Exact(super::cover::DELEGATE),
        example: super::cover::DELEGATE,
    },
    // The roads of the contract, each with its token, its key or its pair.
    Route {
        method: Method::Any,
        id: Id::HttpRoad,
        reach: Reach::Token,
        matches: Pattern::Fn(http_road::serves),
        example: "/v1/http/open/host/22",
    },
    Route {
        method: Method::Get,
        id: Id::Connect,
        reach: Reach::Token,
        matches: Pattern::Prefix("/connect/"),
        example: "/connect/host/22",
    },
    Route {
        method: Method::Get,
        id: Id::Layer,
        reach: Reach::Token,
        matches: Pattern::Fn(layer::serves),
        example: "/v1/layer/host/22",
    },
    Route {
        method: Method::Any,
        id: Id::Mailbox,
        reach: Reach::Token,
        matches: Pattern::Fn(mailbox::serves),
        example: "/v1/mailbox",
    },
    Route {
        method: Method::Any,
        id: Id::Leg,
        reach: Reach::Token,
        matches: Pattern::Fn(leg::serves),
        example: "/v1/leg/p-1/0",
    },
    Route {
        method: Method::Any,
        id: Id::Reverse,
        reach: Reach::Token,
        matches: Pattern::Fn(reverse::serves),
        example: "/v1/pair",
    },
    Route {
        method: Method::Any,
        id: Id::Derp,
        reach: Reach::Token,
        matches: Pattern::Fn(derp_serves),
        example: "/derp",
    },
    Route {
        method: Method::Any,
        id: Id::Meet,
        reach: Reach::Token,
        matches: Pattern::Fn(meet::serves),
        example: "/ping",
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    /// T-767 (SURF-3): the list of public routes, and the reach of each. A
    /// route added to `ROUTES` fails here until it is reviewed and listed;
    /// a handler with no row is unreachable, which the router's `None` says.
    #[test]
    fn every_public_route_is_in_the_allow_list() {
        let stated: &[(Method, Id, Reach, &str)] = &[
            (Method::Any, Id::Mint, Reach::Open, "/v1/mint"),
            (Method::Get, Id::Health, Reach::Local, "/health"),
            (Method::Get, Id::Relays, Reach::Local, "/relays.json"),
            (Method::Get, Id::Trace, Reach::Local, "/trace"),
            (Method::Get, Id::Spec, Reach::Local, "/llms-full.txt"),
            (Method::Any, Id::Probe, Reach::Local, "/v1/probe/drip"),
            (Method::Any, Id::Delegate, Reach::Token, "/v1/delegate"),
            (Method::Any, Id::HttpRoad, Reach::Token, "/v1/http/open/host/22"),
            (Method::Get, Id::Connect, Reach::Token, "/connect/host/22"),
            (Method::Get, Id::Layer, Reach::Token, "/v1/layer/host/22"),
            (Method::Any, Id::Mailbox, Reach::Token, "/v1/mailbox"),
            (Method::Any, Id::Leg, Reach::Token, "/v1/leg/p-1/0"),
            (Method::Any, Id::Reverse, Reach::Token, "/v1/pair"),
            (Method::Any, Id::Derp, Reach::Token, "/derp"),
            (Method::Any, Id::Meet, Reach::Token, "/ping"),
        ];
        assert_eq!(ROUTES.len(), stated.len(), "a route was added or removed without a row here");
        for (route, (method, id, reach, example)) in ROUTES.iter().zip(stated) {
            assert_eq!((route.method, route.id, route.reach), (*method, *id, *reach), "the row of {example} changed");
            // The row's own example is a request that reaches this row, so
            // that a live test can send one request to every route. A road
            // that this build does not serve (DERP without its feature, Meet
            // without --relay-roads) has an example that no listener matches;
            // the live test skips that row by the same test.
            match classify(route.method.as_str(), route.example).map(|r| r.id) {
                Some(id) => assert_eq!(id, route.id, "{example}"),
                None => assert!(matches!(route.id, Id::Derp | Id::Meet), "the example of {example} is not this row's"),
            }
        }
        // A path that is no route is none, and a method that a route does not
        // take is none too.
        for other in ["/", "/healthz", "/v1/", "/v1/delegate/x", "/relay"] {
            assert_eq!(classify("GET", other).map(|r| r.id), None, "{other}");
        }
        assert!(classify("POST", "/health").is_none(), "a document is a GET");
        assert_eq!(classify("GET", "/v1/mint").map(|r| r.id), Some(Id::Mint), "the mint is any method here");
        assert_eq!(classify("POST", "/v1/mint").map(|r| r.id), Some(Id::Mint));
    }

    /// Under a cover, the documents and the probes are not public, while the
    /// mint and the token's roads are (SURF-1, SURF-2).
    #[test]
    fn a_cover_moves_the_documents_and_keeps_the_mint() {
        for (id, moved) in [
            (Id::Health, true),
            (Id::Relays, true),
            (Id::Trace, true),
            (Id::Spec, true),
            (Id::Probe, true),
            (Id::Mint, false),
            (Id::Connect, false),
            (Id::Delegate, false),
            (Id::Reverse, false),
        ] {
            let route = ROUTES.iter().find(|r| r.id == id).expect("a route");
            assert_eq!(route.reach == Reach::Local, moved, "{id:?}");
        }
    }
}
