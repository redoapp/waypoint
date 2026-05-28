{ pkgs, lib, config, ... }:

{
  languages.go.enable = true;
  languages.go.package = pkgs.go_1_26;

  packages = with pkgs; [
    gotools
    golangci-lint
    delve
    git
    nodejs_22
    nodePackages.pnpm
  ];

  env = {
    GOPATH = "${config.devenv.state}/go";
    GOCACHE = "${config.devenv.state}/go-cache";
    GOMODCACHE = "${config.devenv.state}/go-mod-cache";
    # Ryuk (testcontainers reaper) cannot access the Docker socket inside
    # rootless Podman containers. Disable it; test cleanup handles teardown.
    TESTCONTAINERS_RYUK_DISABLED = "true";
  };

  services.redis.enable = true;

  git-hooks.hooks = {
    gofmt.enable = true;
    golangci-lint.enable = true;
  };

  scripts.run-proxy.exec = ''
    if [ -f .env ]; then
      set -a
      . .env
      set +a
    fi
    mkdir -p .waypoint/tsnet-state
    exec go run ./cmd/waypoint -config waypoint-dev.toml
  '';

  scripts.debug-proxy.exec = ''
    if [ -f .env ]; then
      set -a
      . .env
      set +a
    fi
    mkdir -p .waypoint/tsnet-state
    exec dlv debug ./cmd/waypoint -- -config waypoint-dev.toml
  '';

  scripts.test.exec = ''
    go test ./... "$@"
  '';

  scripts.coverage.exec = ''
    bash scripts/coverage.sh "$@"
  '';

  scripts.coverage-unit.exec = ''
    SKIP_INTEGRATION=1 bash scripts/coverage.sh "$@"
  '';

  scripts.coverage-serve.exec = ''
    SERVE=":8080" bash scripts/coverage.sh "$@"
  '';

  scripts.docs-dev.exec = ''
    cd "${config.devenv.root}/website"
    pnpm install
    exec pnpm dev
  '';

  scripts.docs-build.exec = ''
    cd "${config.devenv.root}/website"
    pnpm install --frozen-lockfile
    exec pnpm build
  '';

  enterShell = ''
    echo "Go: $(go version)"
    echo "Valkey service configured (start with 'devenv up')"
    echo "Commands: run-proxy, debug-proxy, test, coverage, coverage-unit, coverage-serve, docs-dev, docs-build"
  '';
}
