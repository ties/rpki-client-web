# -*- mode: ruby -*-
# vi: set ft=ruby :
Vagrant.configure("2") do |config|
  config.vm.box = "generic/fedora35"

  config.vm.network "forwarded_port", guest: 8888, host: 8888, host_ip: "127.0.0.1"

  config.vm.provider "virtualbox" do |vb|
    vb.memory = "4096"
    vb.cpus = 4
  end
  
  config.vm.synced_folder ".", "/src"

  config.vm.provision "shell", inline: <<-SHELL
    dnf upgrade -y --refresh
    # neovim, jq: for development
    dnf install -y python-devel rpki-client pipenv neovim jq
    wget https://www.arin.net/resources/manage/rpki/arin.tal -O /etc/pki/tals/arin.tal
  SHELL
end
