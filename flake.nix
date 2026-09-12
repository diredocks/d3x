{
  description = "sleepy 802.1x client";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
      in
      {
        packages.default = pkgs.stdenv.mkDerivation rec {
          pname = "zzz";
          version = "0.1.1";

          src = ./.;

          nativeBuildInputs = with pkgs; [
            meson
            ninja
            pkg-config
          ];

          buildInputs = with pkgs; [
            libpcap
            libevent
          ];

          meta = with pkgs.lib; {
            description = "sleepy 802.1x client";
            homepage = "https://github.com/diredocks/zzz";
          };
        };

        devShells.default = pkgs.mkShell {
          inputsFrom = [ self.packages.${system}.default ];
          
          buildInputs = with pkgs; [
            zig
            gdb
            valgrind
            clang-tools
            bear
          ];
        };
      }
    );
}
