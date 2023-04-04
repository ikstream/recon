#!/usr/bin/awk -f
# analyze SSH configuration

# invoke this program like this:
# /path/to/this/file /path/to/recon/*/services/ssh*nmap.log

# function to append a value to an array, if that array does not yet contain the value
function append_to_array(array, value) {
  for (i in array) {
    if (value == array[i])
      return
  }
  array[length(array)+1] = value
}

BEGIN {
  auth_methods = "authentication method"
  kex_algorithms = "key exchange method"
  server_host_key_algorithms = "server host key algorithm"
  encryption_algorithms = "encryption algorithm"
  mac_algorithms = "MAC algorithm"

  state = ""
}

/^# Nmap .+ scan initiated/ {
  host = $NF
  next
}

/tcp open/ && /ssh/ {
  split($0, ports, "/")
  port = ports[1]
  printf "\n## %s:%s\n\n", host, port

  service = host ":" port

  if ($0 ~ /protocol/ && $0 !~ /protocol 2/) {
    match($0, /protocol (1|2)(\.[0-9])?/)
    printf "* insecure protocol version: %s\n", substr($0, RSTART, RLENGTH)
    append_to_array(hosts, host)
    append_to_array(services, service)
  }

  state = "port"
  next
}

# a state starts with `|` and is followed with at least a single but most three spaces
/\| (  )?[^ ]/ {
  state = "???"
}

/Supported authentication methods:/ {
  state = auth_methods
  next
}

/kex_algorithms/ {
  state = kex_algorithms
  next
}

/server_host_key_algorithms/ {
  state = server_host_key_algorithms
  next
}

/encryption_algorithms/ {
  state = encryption_algorithms
  next
}

/mac_algorithms/ {
  state = mac_algorithms
  next
}

(state == auth_methods) && ! /publickey/ {
  printf "* weak %s: `%s`\n", state, $2
  append_to_array(hosts, host)
  append_to_array(services, service)
  next
}

(state == kex_algorithms) && ! ( /diffie-hellman-group-exchange-sha256/ || /diffie-hellman-group14-sha256/ || /diffie-hellman-group1(5|6|8)-sha512/ || /rsa2048-sha256/ || /ecdh-sha2-nistp(256|384|521)/ || /curve25519-sha256/ ) {
  printf "* weak %s: `%s`\n", state, $2
  append_to_array(hosts, host)
  append_to_array(services, service)
  next
}

(state == server_host_key_algorithms) && ! ( /pgp-sign-dss/ || /ecdsa-sha2-nistp(256|384|521)/ || /x509v3-ecdsa-sha2-nistp(256|384|521)/ || /rsa-sha2-(256|512)/ || /ssh-ed25519/ ) {
  printf "* weak %s: `%s`\n", state, $2
  append_to_array(hosts, host)
  append_to_array(services, service)
  next
}

(state == encryption_algorithms) && ! ( /AEAD_AES_(128|256)_GCM/ || /aes(128|192|256)-(cbc|ctr|gcm)/ || /chacha20-poly1305/ ) {
  printf "* weak %s: `%s`\n", state, $2
  append_to_array(hosts, host)
  append_to_array(services, service)
  next
}

(state == mac_algorithms) && ! ( /hmac-sha2-(256|512)(-etm)?/ || /umac-128(-etm)?/ ) {
  printf "* weak %s: `%s`\n", state, $2
  append_to_array(hosts, host)
  append_to_array(services, service)
  next
}

END {
  printf "\n# affected services\n\n"
  for (i in services) {
    printf "* `%s`\n", services[i]
  }

  printf "\n# affected hosts\n\n"
  for (i in hosts) {
    printf "* `%s`\n", hosts[i]
  }
}