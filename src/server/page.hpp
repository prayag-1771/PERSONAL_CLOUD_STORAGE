#pragma once

#include <string>

namespace pcs {
namespace server {

// The single-page web client, compiled in so the server stays one binary
// with no files to install alongside it.
//
// The page is a real client, not a thin shell: it derives keys and seals and
// opens files in the browser with WebCrypto, using the same container format
// as the command-line client. The passphrase never leaves the tab, and what
// travels over HTTP is already ciphertext.
const std::string& web_page();

}  // namespace server
}  // namespace pcs
