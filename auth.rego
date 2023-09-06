package authz

import future.keywords

default allow = false

allow {
  input.username == "admin"
  groups = ["write", "read"]
  input.action in groups
}

allow {
  input.username == "user"
  groups = ["read"]
  input.action in groups
}