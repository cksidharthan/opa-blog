package authz

# Test allow rule for writer
test_allow_writer_write {
  allow with input as {"username": "admin", "action": "write"}
}

test_allow_writer_read {
  allow with input as {"username": "admin", "action": "read"}
}

# Test allow rule for user
test_allow_user_read {
  allow with input as {"username": "user", "action": "read"}
}

test_deny_user_write {
  not allow with input as {"username": "user", "action": "write"}
}

# Test default deny
test_default_deny {
  not allow with input as {"username": "unknown", "action": "something"}
}
