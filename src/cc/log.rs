use std::env;
use std::sync::Once;

static mut USE_CCLOG: bool = false;
static INIT_ONCE: Once = Once::new();

pub fn log_init() -> bool {
    unsafe {
        INIT_ONCE.call_once(|| {
            if env::var_os("QUICHE_CCLOG").is_some() {
                USE_CCLOG = true;
                ::log::log!(::log::Level::Error, "CC Logging initialized");
            }
        });

        USE_CCLOG
    }
}

/// Logging for Congestion Control.
///
/// Use cclog!() macro for CC logging.
/// Will be displayed only when QUICHE_CCLOG environment variable is set.
#[macro_export]
macro_rules! cclog {
    ($($arg:tt)*) => ( {
        if cc::log::log_init() { ::log::log!(::log::Level::Error, $($arg)*); }} );
}
