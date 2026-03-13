{ pkgs, lib, config, ... }:

{
  languages.go.enable = true;
  languages.go.package = pkgs.go_1_26;

  packages = with pkgs; [
    gotools
    golangci-lint
    delve
    git
  ];

  env = {
    GOPATH = "${config.devenv.state}/go";
    GOCACHE = "${config.devenv.state}/go-cache";
    GOMODCACHE = "${config.devenv.state}/go-mod-cache";
  };

  services.redis.enable = true;

  git-hooks.hooks = {
    gofmt.enable = true;
    golangci-lint.enable = true;
  };

  scripts.test.exec = ''
    go test ./... "$@"
  '';

  scripts.coverage.exec = ''
    mkdir -p coverage
    go test -coverprofile=coverage/coverage.out -covermode=atomic ./... "$@"
    go tool cover -func=coverage/coverage.out
    go tool cover -html=coverage/coverage.out -o coverage/coverage.html
    echo ""
    echo "Coverage report: coverage/coverage.html"
  '';

  enterShell = ''
    echo "Go: $(go version)"
    echo "Valkey service configured (start with 'devenv up')"
    echo "Commands: test, coverage"
  '';
}
