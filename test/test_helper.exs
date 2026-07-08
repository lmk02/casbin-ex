# Integration tests against real infrastructure are opt-in:
#
#     docker compose -f test/docker/docker-compose.yml up -d
#     mix test --include redis
#
ExUnit.start(exclude: [:redis, :postgres])
