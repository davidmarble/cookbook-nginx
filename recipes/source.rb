#
# Cookbook Name:: nginx
# Recipe:: source
#
# Author:: Adam Jacob (<adam@opscode.com>)
# Author:: Joshua Timberman (<joshua@opscode.com>)
#
# Copyright 2009-2011, Opscode, Inc.
#
# Edited:: David Marble (<davidmarble@gmail.com>)
#   Support custom nginx modules via node[:nginx][:modules]:
#       * tcp_proxy
#   Custom sites via node[:nginx][:sites]
#   Custom nginx.conf via node[:nginx][:config_cookbook]
#   Subscribe reload when recompile
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

include_recipe "build-essential"

packages = value_for_platform(
    ["centos","redhat","fedora"] => {'default' => ['pcre-devel', 'openssl-devel', 'zlib', 'zlib-devel']},
    "default" => ['libpcre3', 'libpcre3-dev', 'libssl-dev', 'zlib1g-dev', 'libpcrecpp0']
    )

packages.each do |devpkg|
    package devpkg
end

user node[:nginx][:user] do
    system true
    shell "/bin/false"
    home "/var/www"
end

nginx_version = node[:nginx][:version]
src_url = node[:nginx][:url]

node.set[:nginx][:install_path]    = "/opt/nginx-#{nginx_version}"
node.set[:nginx][:src_binary]      = "#{node[:nginx][:install_path]}/sbin/nginx"

# If using runit or bluepill, daemon mode can be turned off
# See daemon directive in http://wiki.nginx.org/CoreModule
node.set[:nginx][:daemon_disable]  = ["bluepill","runit"].include?(node[:nginx][:init_style])
node.set[:nginx][:configure_flags] = [
    "--prefix=#{node[:nginx][:install_path]}",
    "--conf-path=#{node[:nginx][:dir]}/nginx.conf",
    "--with-http_ssl_module",
    "--with-http_gzip_static_module",
    "--with-http_realip_module",
    "--http-log-path=/var/log/nginx/access.log",
    "--error-log-path=/var/log/nginx/error.log",
    "--pid-path=/var/run/nginx.pid",
    "--lock-path=/var/lock/subsys/nginx",
    "--user=#{node[:nginx][:user]}",
    "--group=#{node[:nginx][:user]}"
]

remote_file "#{Chef::Config[:file_cache_path]}/nginx-#{nginx_version}.tar.gz" do
    source src_url
    action :create_if_missing
end

bash "extract_nginx_source" do
    cwd Chef::Config[:file_cache_path]
    code <<-EOH
        tar zxf nginx-#{nginx_version}.tar.gz
    EOH
end

if node[:nginx][:modules].include?("tcp_proxy")
    bash "add_tcp_proxy_module" do
        cwd Chef::Config[:file_cache_path]
        code <<-EOH
        if [[ -d "nginx_tcp_proxy_module" ]]; then
            cd nginx_tcp_proxy_module && git pull
            cd #{Chef::Config[:file_cache_path]}
        else
            env GIT_SSL_NO_VERIFY=true git clone https://github.com/yaoweibin/nginx_tcp_proxy_module.git
        fi
        cd nginx-#{nginx_version} && patch -p1 < ../nginx_tcp_proxy_module/tcp.patch
        EOH
    end
    node[:nginx][:configure_flags] << "--add-module=../nginx_tcp_proxy_module"
end

configure_flags = node[:nginx][:configure_flags].join(" ")

bash "compile_nginx_source" do
    cwd Chef::Config[:file_cache_path]
    code <<-EOH
        cd nginx-#{nginx_version} && ./configure #{configure_flags}
        make && make install
    EOH
    creates node[:nginx][:src_binary]
end

directory node[:nginx][:log_dir] do
    mode 0755
    owner node[:nginx][:user]
    action :create
end

["/var/tmp/nginx/client", "/var/tmp/nginx/proxy"].each do |d|
    directory d do
        mode 0755
        owner node[:nginx][:user]
        recursive true
        action :create
    end
end

directory node[:nginx][:dir] do
    owner "root"
    group "root"
    mode "0755"
end

case node[:nginx][:init_style]
when "runit"
    include_recipe "runit"

    runit_service "nginx"

    service "nginx" do
        supports :status => true, :restart => true, :reload => true
        reload_command "[[ -f #{node[:nginx][:pid]} ]] && kill -HUP `cat #{node[:nginx][:pid]}` || true"
        subscribes :reload, resources(:bash => "compile_nginx_source")
    end
when "bluepill"
    include_recipe "bluepill"

    template "#{node['bluepill']['conf_dir']}/nginx.pill" do
        source "nginx.pill.erb"
        mode 0644
        variables(
            :working_dir => node[:nginx][:install_path],
            :src_binary => node[:nginx][:src_binary],
            :nginx_dir => node[:nginx][:dir],
            :log_dir => node[:nginx][:log_dir],
            :pid => node[:nginx][:pid]
        )
    end

    bluepill_service "nginx" do
        action [ :enable, :load ]
    end

    service "nginx" do
        supports :status => true, :restart => true, :reload => true
        reload_command "[[ -f #{node[:nginx][:pid]} ]] && kill -HUP `cat #{node[:nginx][:pid]}` || true"
        subscribes :reload, resources(:bash => "compile_nginx_source")
        action :nothing
    end
else
    node.set[:nginx][:daemon_disable] = false
    #install init script based on platform
    case node['platform']
    when "centos","redhat","fedora"
        template "/etc/init.d/nginx" do
            source "nginx.init.redhat.erb"
            owner "root"
            group "root"
            mode "0755"
        end
    when "ubuntu","debian"
        template "/etc/init.d/nginx" do
            source "nginx.init.debian.erb"
            owner "root"
            group "root"
            mode "0755"
        end
    else
        template "/etc/init.d/nginx" do
            source "nginx.init.erb"
            owner "root"
            group "root"
            mode "0755"
        end
    end

    #install sysconfig file (not really needed but standard)
    # template "/etc/sysconfig/nginx" do
        # source "nginx.sysconfig.erb"
        # owner "root"
        # group "root"
        # mode "0644"
    # end

    #register service
    service "nginx" do
        supports :status => true, :restart => true, :reload => true
        subscribes :restart, resources(:bash => "compile_nginx_source")
        action :enable
    end
end

%w{ sites-available sites-enabled conf.d }.each do |dir|
    directory "#{node[:nginx][:dir]}/#{dir}" do
        owner "root"
        group "root"
        mode "0755"
    end
end

%w{nxensite nxdissite}.each do |nxscript|
    template "/usr/sbin/#{nxscript}" do
        source "#{nxscript}.erb"
        mode "0755"
        owner "root"
        group "root"
    end
end

template "nginx.conf" do
    path "#{node[:nginx][:dir]}/nginx.conf"
    source node[:nginx].attribute?("config_cookbook") ? "etc/nginx/nginx.conf.erb" : "nginx.conf.erb"
    owner "root"
    group "root"
    mode "0644"
    cookbook node[:nginx].attribute?("config_cookbook") ? node[:nginx][:config_cookbook] : "nginx"
    notifies :reload, resources(:service => "nginx"), :immediately
end

cookbook_file "#{node[:nginx][:dir]}/mime.types" do
    source "mime.types"
    owner "root"
    group "root"
    mode "0644"
    notifies :reload, resources(:service => "nginx"), :immediately
end

template "#{node[:nginx][:dir]}/sites-available/default" do
    source "sites-available/default-site.erb"
    owner "root"
    group "root"
    mode "0644"
    notifies :reload, resources(:service => "nginx"), :immediately
end

if node[:nginx].attribute?("sites")
    node[:nginx][:sites].each do |site|
        template "/etc/nginx/sites-enabled/#{site}.conf" do
            source node[:nginx].attribute?("config_cookbook") ? "etc/nginx/sites-available/#{site}.conf.erb" : "sites-available/#{site}.conf.erb"
            owner "root"
            group "root"
            mode "0640"
            cookbook node[:nginx].attribute?("config_cookbook") ? node[:nginx][:config_cookbook] : "nginx"
            notifies :reload, resources(:service => "nginx"), :immediately
        end
    end
else
    directory "/var/www/nginx-default" do
        owner "www-data"
        group "www-data"
        recursive true
        mode "0755"
    end
    link "/etc/nginx/sites-enabled/default" do
        to "/etc/nginx/sites-enabled/default"
    end
end
