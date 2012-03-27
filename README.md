Description
===========

Installs nginx from package OR source code and sets up configuration handling similar to Debian's Apache2 scripts.

Requirements
============

Cookbooks
---------

* build-essential (for nginx::source)
* runit (for nginx::source)

Platform
--------

Debian or Ubuntu though may work where 'build-essential' works, but other platforms are untested.

Attributes
==========

All node attributes are set under the `nginx` namespace.

* version - sets the version to install.
* dir - configuration dir.
* `log_dir` - where logs go.
* user - user to run as.
* binary - path to nginx binary.
* gzip - all attributes under the `gzip` namespace configure the gzip module.
* keepalive - whether to use keepalive.
* `keepalive_timeout` - set the keepalive timeout.
* `worker_processes` - number of workers to spawn.
* `worker_connections` - number of connections per worker.
* `server_names_hash_bucket_size`
* `url` - URL where to download the nginx source tarball

The following attributes are set at the 'normal' node level via the `nginx::source` recipe.

* `install_path` - for nginx::source, sets the --prefix installation.
* `src_binary` - for nginx::source, sets the binary location.
* `configure_flags` - for nginx::source, an array of flags to use for compilation.
* `modules` - for nginx::source, supports custom module compilation. Currently 
only supports tcp_proxy.
* `config_cookbook` - for nginx::source, if defined, sets the cookbook where 
templates for nginx.conf and custom sites are found. For example, if this is 
set to "example", nginx::source expects to find the cookbook "example" with a 
templates/<default>/nginx/nginx.conf.erb file.
* `sites` - for nginx::source, supports an array of custom site configurations. 
For each string in the array, the recipe expects to find 
templates/<default>/sites-available/#{site}.conf.erb unless `config_cookbook` 
is defined, in which case it will expect 
#{node[:nginx][:config_cookbook]}/templates/<default>/nginx/sites-available/#{site}.conf.erb

Usage
=====

Provides two ways to install and configure nginx.

* Install via native package (nginx::default)
* Install via compiled source (nginx::source)

Both recipes implement configuration handling similar to the Debian Apache2 site enable/disable.

There's some redundancy in that the config handling hasn't been separated from the installation method (yet), so use only one of the recipes.

Some of the attributes mentioned above are only set in the `nginx::source` recipe. They can be overridden by setting them via a role in `override_attributes`.

License and Author
==================

Author:: Joshua Timberman (<joshua@opscode.com>)
Author:: Adam Jacob (<adam@opscode.com>)
Author:: AJ Christensen (<aj@opscode.com>)

Copyright:: 2008-2011, Opscode, Inc

Edited:: David Marble (<davidmarble@gmail.com>)
* `modules`, `config_cookbook`, `sites`

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
