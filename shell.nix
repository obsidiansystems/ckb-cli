{ pkgs ? import <nixpkgs> {}}:
(import ./. {}).overrideAttrs (p: {
  nativeBuildInputs = p.nativeBuildInputs ++ [ pkgs.cargo-watch pkgs.rustfmt ];
})
