use crate::quic::ConnectionHook;
use std::sync::Arc;

/// Hook configuration for use in the QUIC connection lifecycle.
///
/// Use these to manage the connection outside of what is possible with an
/// [`ApplicationOverQuic`](crate::ApplicationOverQuic).
#[derive(Default, Clone)]
pub struct Hooks {
    pub connection_hook: Option<Arc<dyn ConnectionHook + Send + Sync + 'static>>,
    // http3_hook: ...
}

impl std::fmt::Debug for Hooks {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        fn hook_status<T>(val: &Option<T>) -> &'static str {
            match val {
                Some(_) => "enabled",
                None => "disabled",
            }
        }

        f.debug_struct("Hooks")
            .field("connection_hook", &hook_status(&self.connection_hook))
            .finish()
    }
}
