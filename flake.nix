{
  description = "Rust development dev shell";

  inputs = {
    nixpkgs.url      = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";
    flake-utils.url  = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, rust-overlay, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs {
          inherit system overlays;
        };
      in
      with pkgs;
      {
        devShells.default = mkShell {
          buildInputs = [
            openssl
            pkg-config
            eza
            fd
           # rustup
            clang
            cmake   # Example: build system
            (pkgs.rust-bin.nightly.latest.rust.override {
              extensions = ["rust-src" "clippy" "rustfmt" "rust-analysis" "rustc" "miri" "rust" "rust-std" "cargo" "rust-analyzer"];
            })
            cargo-audit
          ];

          shellHook = ''
            echo "Dev shell is starting..."
            export CC=$(which gcc)  # Set the C compiler
            export CXX=$(which g++) # Set the C++ compiler
            alias ls=eza
            alias find=fd
            export PATH="$HOME/.cargo/bin:$PATH"
            cargo install cargo-xtask
            cargo install bpf-linker
            cargo install cargo-tarpaulin
            export PATH="$HOME/.cargo/bin:$PATH"

           # Store the project root directory
            export PROJECT_ROOT=$(pwd)

            # Override the cd command
            function cd() {
              # Get the absolute path of the target directory
              target_dir=$(readlink -f "$1")
              if [[ "$target_dir" != "$PROJECT_ROOT"* ]]; then
                echo "Navigation outside the project root is not allowed"
              else
                builtin cd "$1"
              fi
            }

            echo "Welcome to Devshell..."

          '';
        };
      }
    );
}
