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
    bash scripts/coverage.sh "$@"
  '';

  scripts.coverage-unit.exec = ''
    SKIP_INTEGRATION=1 bash scripts/coverage.sh "$@"
  '';

  scripts.coverage-serve.exec = ''
    SERVE=":8080" bash scripts/coverage.sh "$@"
  '';

  enterShell = ''
    echo "Go: $(go version)"
    echo "Valkey service configured (start with 'devenv up')"
    echo "Commands: test, coverage, coverage-unit, coverage-serve"
  '';
}
