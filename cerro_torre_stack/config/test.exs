# SPDX-License-Identifier: MPL-2.0
import Config

# We don't run a server during test. If one is required,
# you can enable the server option below.
config :svalinn, SvalinnWeb.Endpoint,
  http: [ip: {127, 0, 0, 1}, port: 4002],
  secret_key_base:
    System.get_env("SECRET_KEY_BASE") ||
      # Dev/test only. Deliberately built at runtime rather than written
      # as a 64-character literal, so nothing credential-shaped is ever
      # committed. config/runtime.exs raises if SECRET_KEY_BASE is unset,
      # so production cannot reach this fallback.
      String.duplicate("dev-only-not-a-secret-", 4),
  server: false

# In test we don't send emails
config :svalinn, Svalinn.Mailer, adapter: Swoosh.Adapters.Test

# Disable swoosh api client as it is only required for production adapters
config :swoosh, :api_client, false

# Print only warnings and errors during test
config :logger, level: :warning

# Initialize plugs at runtime for faster test compilation
config :phoenix, :plug_init_mode, :runtime

# Sort query params output of verified routes for robust url comparisons
config :phoenix,
  sort_verified_routes_query_params: true
