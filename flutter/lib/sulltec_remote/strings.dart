/// The fork's own strings for the Flutter UI.
///
/// Dart cannot read `hbb_common::sulltec_remote`, so these are the second home for values the Rust
/// side also holds. Two files, one per language — not eighteen literals spread across the pages
/// that happen to link somewhere.
///
/// ⚠ **Keep in step with `libs/hbb_common/src/sulltec_remote.rs`.** Where a value exists on both
/// sides the names match deliberately, so a change on one is greppable on the other.
library;

/// The product's own page. Everything below it is a child of this path.
const kSiteHome = 'https://www.sulltec.com/';

/// What a link shows when the text is the site rather than the address.
const kSiteHomeLabel = 'www.sulltec.com';

/// Where a build is fetched. Not a direct file link: the page explains that an installer carries
/// the deployment's server settings, which a build taken from anywhere else does not.
const kDownload = 'https://www.sulltec.com/SullTecRemote/download/';

/// What the product costs.
const kPricing = 'https://www.sulltec.com/SullTecRemote/pricing/';

/// The privacy policy. The site also answers `/Privacy`, which redirects here — this names the
/// destination so a client does not spend a round trip discovering it.
const kPrivacy = 'https://www.sulltec.com/privacy-policy/';

/// Wayland cannot be captured, so a session connects and shows black until the desktop is on X11.
const kDocsX11Required = 'https://www.sulltec.com/SullTecRemote/docs/linux/#x11-required';

/// Reaching a Linux box before anyone has signed in, which needs the client running as a service.
const kDocsLinuxLoginScreen = 'https://www.sulltec.com/SullTecRemote/docs/linux/#login-screen';

/// A Linux session that shows the screen but ignores input.
const kDocsLinuxPermissions =
    'https://www.sulltec.com/SullTecRemote/docs/linux/#permissions-issue';
