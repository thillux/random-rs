{
  inputs.nixpkgs.url = "github:nixos/nixpkgs";

  outputs = { self, nixpkgs }:
  let
    pkgs = nixpkgs.legacyPackages.x86_64-linux;
  in {
    devShells.x86_64-linux.default = pkgs.mkShell {
      buildInputs = with pkgs; [
        libp11
        openssl
        opensc
        gdb
        pkcs11helper
        tpm2-pkcs11
        tpm2-tools
      ];
      nativeBuildInputs = with pkgs; [
        pkg-config
      ];
    };
  };
}
