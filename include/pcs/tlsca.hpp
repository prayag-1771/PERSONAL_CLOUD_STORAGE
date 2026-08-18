#pragma once

#include <string>
#include <vector>

// A small private certificate authority.
//
// The server mints a CA once, then issues itself a certificate signed by it.
// Install the CA certificate on each device and the browser stops warning,
// which matters as soon as anyone is typing a password into a page. It also
// lets the command-line client verify who it is talking to, instead of
// accepting whatever certificate it is handed.
//
// The CA is meant to be shared by a group of machines: copy ca.crt and ca.key
// to each server so they all issue certificates under the same authority, and
// every client then trusts the whole group with one file.
namespace pcs {

// Creates the CA if it is not already there. Existing files are left alone,
// so restarting a server never invalidates certificates already installed on
// somebody's phone.
bool ensure_ca(const std::string& ca_cert_path, const std::string& ca_key_path,
               std::string& error);

// Issues a server certificate signed by the CA, valid for every name and
// address in `hosts`. Browsers ignore the common name and look only at the
// subject alternative names, so every way the server might be addressed has
// to be listed here.
bool issue_server_cert(const std::string& ca_cert_path,
                       const std::string& ca_key_path,
                       const std::string& cert_path,
                       const std::string& key_path,
                       const std::vector<std::string>& hosts,
                       std::string& error);

// True when the certificate is missing, unreadable, expiring within
// `days_left`, or does not cover every host in `hosts`. Any of those means it
// should be reissued.
bool server_cert_needs_reissue(const std::string& cert_path,
                               const std::vector<std::string>& hosts,
                               int days_left);

// The names and addresses this machine can be reached by: its hostname, the
// addresses that resolve to it, and the loopback entries. Callers add
// anything else with --host.
std::vector<std::string> local_host_identities();

// True if the text is a literal IPv4 or IPv6 address rather than a name.
// Verification differs between the two, since a name is matched against the
// DNS entries and an address against the IP entries.
bool looks_like_ip(const std::string& host);

}  // namespace pcs
