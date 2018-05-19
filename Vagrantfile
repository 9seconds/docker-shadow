# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|
  config.vm.box = "ubuntu/bionic64"
  config.vm.box_check_update = false

  config.vm.network "private_network", ip: "10.0.0.100"
  config.vm.synced_folder "./docker", "/vagrant"

  config.vm.provider "virtualbox" do |vb|
    vb.gui    = false
    vb.cpus   = 1
    vb.memory = 512
  end

  config.vm.provision 'ansible' do |ansible|
    ansible.playbook           = 'provision/site.yaml'
    ansible.compatibility_mode = '2.0'
  end
end
