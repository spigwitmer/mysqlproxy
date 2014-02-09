"""
Plugin framework
"""
import logging
import os
import imp
import sys

# this stops python from whining about trying to get logging
# handlers for a module that doesn't really exist
sys.modules['mysqlproxy_plugins'] = imp.new_module('mysqlproxy_plugins')

_LOG = logging.getLogger(__name__)


class PluginError(Exception):
    pass


class PluginRegistry(object):
    """
    Each Session has its own plugin set as such
    """
    def __init__(self):
        self.plugins = {} # {'plugin_name': [plugin_1, plugin_2]}

    def call_hooks(self, hook_name, *largs, **kwargs):
        """
        This is called for every hook entry 
        in mysqlproxy core.  It should return a tuple of:
        (do_continue, return_value)
        `do_continue` (True/False) -- a plugin subscribed to 
            the given hook name returned a replacement
            value. i.e. True for 'authenticate' would
            short-circuit mysqlproxy.Session logic for authentication
        `return_val` -- context-dependent return value.
        """
        do_cont, ret_val = (True, None)
        if hook_name in self.plugins:
            for plugin in self.plugins[hook_name]:
                try:
                    do_cont, ret_val = plugin.run(hook_name, *largs, **kwargs)
                    if do_cont == False:
                        break
                except PluginError as ex:
                    _LOG.warning('Plugin %s reported error in %s: %s' % 
                        (plugin.plugin_name, hook_name, ex))
                except Exception as ex:
                    _LOG.warning('Exception during %s processing hook %s: %s' % 
                        (plugin.plugin_name, hook_name, ex))
        return do_cont, ret_val

    def _discover_plugins(self, plugins_dir):
        for root, dirs, files in os.walk(plugins_dir):
            for fname in files:
                if fname.endswith('.py'):
                    mod_name = fname[:-3].replace('/', '.')
                    mod = imp.load_module('mysqlproxy_plugins.%s' % mod_name,
                        *imp.find_module(mod_name, [root]))
                    for some_attr in dir(mod):
                        mod_attr = getattr(mod, some_attr)
                        if Plugin in getattr(mod_attr, '__bases__', []):
                            yield mod_attr()

    def add_all_plugins(self, plugins_dir):
        for plugin in self._discover_plugins(plugins_dir):
            for hook_name in plugin.hooks:
                if hook_name not in self.plugins:
                    self.plugins[hook_name] = []
                self.plugins[hook_name].append(plugin)


class Plugin(object):
    def run(self, *largs, **kwargs):
        raise NotImplementedError('mysqlproxy.Plugin.run()')
