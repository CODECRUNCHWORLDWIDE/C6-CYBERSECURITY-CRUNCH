{ pkgs }: {
  deps = [
    pkgs.nano
    pkgs.vimHugeX
    pkgs.bashInteractive
    pkgs.nodePackages.bash-language-server
    pkgs.man
  ];
}