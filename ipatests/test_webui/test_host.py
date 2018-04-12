# Authors:
#   Petr Vobornik <pvoborni@redhat.com>
#
# Copyright (C) 2013  Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

"""
Host tests
"""

from ipatests.test_webui.ui_driver import UI_driver
from ipatests.test_webui.ui_driver import screenshot
import ipatests.test_webui.data_hostgroup as hostgroup
import ipatests.test_webui.data_netgroup as netgroup
import ipatests.test_webui.data_hbac as hbac
import ipatests.test_webui.test_rbac as rbac
import ipatests.test_webui.data_sudo as sudo
import pytest

ENTITY = 'host'


@pytest.mark.tier1
class host_tasks(UI_driver):

    def setup(self, *args, **kwargs):
        super(host_tasks, self).setup(*args, **kwargs)
        self.prep_data()
        self.prep_data2()

    def prep_data(self):
        host = 'itest'
        domain = self.config.get('ipa_domain')
        ip = self.get_ip()
        self.data = self.get_data(host, domain, ip)
        self.pkey = self.data['pkey']
        return self.data

    def prep_data2(self):
        host = 'itest2'
        domain = self.config.get('ipa_domain')
        self.data2 = self.get_data(host, domain)
        self.pkey2 = self.data2['pkey']
        return self.data2

    def get_data(self, host, domain, ip=None):
        if self.has_dns():
            add_data = [
                ('textbox', 'hostname', host),
                ('combobox', 'dnszone', domain+'.'),
            ]
            if ip:
                add_data.append(('textbox', 'ip_address', ip))
            add_data.append(('checkbox', 'force', None))
            del_data = [
                ('checkbox', 'updatedns', None)
            ]
        else:
            add_data = [
                ('textbox', 'fqdn', '%s.%s' % (host, domain)),
                ('checkbox', 'force', None),
            ]
            del_data = None

        data = {
            'pkey': '%s.%s' % (host, domain),
            'add': add_data,
            'mod': [
                ('textarea', 'description', 'Desc'),
            ],
            'del': del_data,
        }

        return data

    def get_ip(self):
        """
        Get next IP
        """
        ip = self.config.get('ipa_ip')
        if not ip:
            self.skip('FreeIPA Server IP address not configured')
        ip = ip.split('.')
        last = int(ip.pop())
        ip.append(str(last + 1))
        return '.'.join(ip)

    def load_file(self, path):
        with open(path, 'r') as file_d:
            content = file_d.read()
        return content


@pytest.mark.tier1
class test_host(host_tasks):

    @screenshot
    def test_crud(self):
        """
        Basic CRUD: host
        """
        self.init_app()
        self.basic_crud(ENTITY, self.data)

    @screenshot
    def test_certificates(self):
        """
        Test host certificate actions

        Requires to have CA installed and 'host_csr_path' configuration option
        set.
        """

        if not self.has_ca():
            self.skip('CA is not configured')

        csr_path = self.config.get('host_csr_path')
        if not csr_path:
            self.skip('CSR file is not configured')

        self.init_app()
        # ENHANCEMENT: generate csr dynamically
        csr = self.load_file(csr_path)
        cert_widget_sel = "div.certificate-widget"

        self.add_record(ENTITY, self.data)
        self.navigate_to_record(self.pkey)

        # cert request
        self.action_list_action('request_cert', confirm=False)
        self.assert_dialog()
        self.fill_text("textarea[name='csr']", csr)
        self.dialog_button_click('issue')
        self.wait_for_request(n=2, d=3)
        self.assert_visible(cert_widget_sel)

        # cert view
        self.action_list_action('view', confirm=False,
                                parents_css_sel=cert_widget_sel)
        self.assert_dialog()
        self.dialog_button_click('close')

        # cert get
        self.action_list_action('get', confirm=False,
                                parents_css_sel=cert_widget_sel)
        self.assert_dialog()
        # check that the textarea is not empty
        self.assert_empty_value('textarea.certificate', negative=True)
        self.dialog_button_click('close')

        # cert download - we can only try to click the download action
        self.action_list_action('download', confirm=False,
                                parents_css_sel=cert_widget_sel)

        # check that revoke action is enabled
        self.assert_action_list_action('revoke',
                                       parents_css_sel=cert_widget_sel,
                                       facet_actions=False)

        # check that remove_hold action is not enabled
        self.assert_action_list_action('remove_hold', enabled=False,
                                       parents_css_sel=cert_widget_sel,
                                       facet_actions=False)

        # cert revoke
        self.action_list_action('revoke', confirm=False,
                                parents_css_sel=cert_widget_sel)
        self.wait()
        self.select('select', '6')
        self.dialog_button_click('ok')
        self.wait_for_request(n=2, d=3)
        self.assert_visible(cert_widget_sel + " div.watermark")

        # check that revoke action is not enabled
        self.assert_action_list_action('revoke', enabled=False,
                                       parents_css_sel=cert_widget_sel,
                                       facet_actions=False)

        # check that remove_hold action is enabled
        self.assert_action_list_action('remove_hold',
                                       parents_css_sel=cert_widget_sel,
                                       facet_actions=False)

        # cert remove hold
        self.action_list_action('remove_hold', confirm=False,
                                parents_css_sel=cert_widget_sel)
        self.wait()
        self.dialog_button_click('ok')
        self.wait_for_request(n=2)

        # check that revoke action is enabled
        self.assert_action_list_action('revoke',
                                       parents_css_sel=cert_widget_sel,
                                       facet_actions=False)

        # check that remove_hold action is not enabled
        self.assert_action_list_action('remove_hold', enabled=False,
                                       parents_css_sel=cert_widget_sel,
                                       facet_actions=False)

        # cleanup
        self.navigate_to_entity(ENTITY, 'search')
        self.delete_record(self.pkey, self.data.get('del'))

    @screenshot
    def test_arbitrary_certificates(self):
        """
        Test managing host arbitrary certificate.

        Requires to have 'arbitrary_cert_path' configuration set.
        """
        cert_path = self.config.get('arbitrary_cert_path')
        if not cert_path:
            self.skip('Arbitrary certificate file is not configured')

        self.init_app()
        cert = self.load_file(cert_path)
        self.add_record(ENTITY, self.data)

        self.navigate_to_record(self.pkey)

        # check whether certificate section is present
        self.assert_visible("div[name='certificate']")

        # add certificate
        self.button_click('add', parents_css_sel="div[name='certificate']")
        self.assert_dialog()
        self.fill_textarea('new_cert', cert)
        self.dialog_button_click('add')

        self.assert_visible("div.certificate-widget")

        # cert view
        self.action_list_action('view', confirm=False,
                                parents_css_sel="div.certificate-widget")
        self.assert_dialog()
        self.dialog_button_click('close')

        # cert get
        self.action_list_action('get', confirm=False,
                                parents_css_sel="div.certificate-widget")
        self.assert_dialog()

        # check that the textarea is not empty
        self.assert_empty_value('textarea.certificate', negative=True)
        self.dialog_button_click('close')

        # cert download - we can only try to click the download action
        self.action_list_action('download', confirm=False,
                                parents_css_sel="div.certificate-widget")

        # check that revoke action is not enabled
        self.assert_action_list_action(
            'revoke', enabled=False,
            parents_css_sel="div.certificate-widget",
            facet_actions=False)

        # check that remove_hold action is not enabled
        self.assert_action_list_action(
            'remove_hold', enabled=False,
            parents_css_sel="div.certificate-widget",
            facet_actions=False)

        # cleanup
        self.navigate_to_entity(ENTITY, 'search')
        self.delete_record(self.pkey, self.data.get('del'))

    @screenshot
    def test_ca_less(self):
        """
        Test host certificate actions in CA-less install
        http://www.freeipa.org/page/V3/CA-less_install
        """
        if self.has_ca():
            self.skip('CA is installed')

        self.init_app()
        self.add_record(ENTITY, self.data)
        self.navigate_to_record(self.pkey)

        self.assert_action_list_action('request_cert', visible=False)

        self.navigate_by_breadcrumb('Hosts')
        self.delete_record(self.pkey, self.data.get('del'))

    @screenshot
    def test_kerberos_flags(self):
        """
        Test Kerberos flags
        http://www.freeipa.org/page/V3/Kerberos_Flags
        """
        name = 'ipakrbokasdelegate'
        mod = {'mod': [('checkbox', name, None)]}
        checked = ['checked']

        self.init_app()
        self.add_record(ENTITY, self.data)
        self.navigate_to_record(self.pkey)

        if self.get_field_checked(name) == checked:
            self.mod_record(ENTITY, mod)  # uncheck

        self.mod_record(ENTITY, mod)
        self.validate_fields([('checkbox', name, checked)])
        self.mod_record(ENTITY, mod)
        self.validate_fields([('checkbox', name, [])])
        self.delete(ENTITY, [self.data])

    @screenshot
    def test_associations(self):
        """
        Host direct associations
        """

        self.init_app()

        # prepare
        # -------
        self.add_record(ENTITY, self.data)
        self.add_record(ENTITY, self.data2, navigate=False)
        self.add_record(hostgroup.ENTITY, hostgroup.DATA)
        self.add_record(netgroup.ENTITY, netgroup.DATA)
        self.add_record(rbac.ROLE_ENTITY, rbac.ROLE_DATA)
        self.add_record(hbac.RULE_ENTITY, hbac.RULE_DATA)
        self.add_record(sudo.RULE_ENTITY, sudo.RULE_DATA)

        # add & remove associations
        # -------------------------
        self.navigate_to_entity(ENTITY)
        self.navigate_to_record(self.pkey)

        self.add_associations([hostgroup.PKEY], facet='memberof_hostgroup', delete=True)
        self.add_associations([netgroup.PKEY], facet='memberof_netgroup', delete=True)
        self.add_associations([rbac.ROLE_PKEY], facet='memberof_role', delete=True)
        self.add_associations([hbac.RULE_PKEY], facet='memberof_hbacrule', delete=True)
        self.add_associations([sudo.RULE_PKEY], facet='memberof_sudorule', delete=True)
        self.add_associations([self.pkey2], facet='managedby_host', delete=True)

        # cleanup
        # -------
        self.delete(ENTITY, [self.data, self.data2])
        self.delete(hostgroup.ENTITY, [hostgroup.DATA])
        self.delete(netgroup.ENTITY, [netgroup.DATA])
        self.delete(rbac.ROLE_ENTITY, [rbac.ROLE_DATA])
        self.delete(hbac.RULE_ENTITY, [hbac.RULE_DATA])
        self.delete(sudo.RULE_ENTITY, [sudo.RULE_DATA])

    @screenshot
    def test_indirect_associations(self):
        """
        Host indirect associations
        """
        self.init_app()

        # add
        # ---
        self.add_record(ENTITY, self.data)

        self.add_record(hostgroup.ENTITY, hostgroup.DATA)
        self.navigate_to_record(hostgroup.PKEY)
        self.add_associations([self.pkey])

        self.add_record(hostgroup.ENTITY, hostgroup.DATA2)
        self.navigate_to_record(hostgroup.PKEY2)
        self.switch_to_facet('member_hostgroup')
        self.add_associations([hostgroup.PKEY])

        self.add_record(netgroup.ENTITY, netgroup.DATA)
        self.navigate_to_record(netgroup.PKEY)
        self.add_table_associations('memberhost_hostgroup', [hostgroup.PKEY2])

        self.add_record(rbac.ROLE_ENTITY, rbac.ROLE_DATA)
        self.navigate_to_record(rbac.ROLE_PKEY)
        self.switch_to_facet('member_hostgroup')
        self.add_associations([hostgroup.PKEY2])

        self.add_record(hbac.RULE_ENTITY, hbac.RULE_DATA)
        self.navigate_to_record(hbac.RULE_PKEY)
        self.add_table_associations('memberhost_hostgroup', [hostgroup.PKEY2])

        self.add_record(sudo.RULE_ENTITY, sudo.RULE_DATA)
        self.navigate_to_record(sudo.RULE_PKEY)
        self.add_table_associations('memberhost_hostgroup', [hostgroup.PKEY2])

        # check indirect associations
        # ---------------------------
        self.navigate_to_entity(ENTITY, 'search')
        self.navigate_to_record(self.pkey)

        self.assert_indirect_record(hostgroup.PKEY2, ENTITY, 'memberof_hostgroup')
        self.assert_indirect_record(netgroup.PKEY, ENTITY, 'memberof_netgroup')
        self.assert_indirect_record(rbac.ROLE_PKEY, ENTITY, 'memberof_role')
        self.assert_indirect_record(hbac.RULE_PKEY, ENTITY, 'memberof_hbacrule')
        self.assert_indirect_record(sudo.RULE_PKEY, ENTITY, 'memberof_sudorule')

        ## cleanup
        ## -------
        self.delete(ENTITY, [self.data])
        self.delete(hostgroup.ENTITY, [hostgroup.DATA, hostgroup.DATA2])
        self.delete(netgroup.ENTITY, [netgroup.DATA])
        self.delete(rbac.ROLE_ENTITY, [rbac.ROLE_DATA])
        self.delete(hbac.RULE_ENTITY, [hbac.RULE_DATA])
        self.delete(sudo.RULE_ENTITY, [sudo.RULE_DATA])
