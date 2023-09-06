package authz

import future.keywords

default allow = false

allow {
  input.role == "admin"
  access_groups = ["write", "read"]
  input.access in access_groups
}

allow {
  input.role == "user"
  access_groups = ["read"]
  input.access in access_groups
}