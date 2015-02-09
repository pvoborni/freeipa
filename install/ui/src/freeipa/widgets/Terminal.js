/*  Authors:
 *    Petr Vobornik <pvoborni@redhat.com>
 *
 * Copyright (C) 2013 Red Hat
 * see file 'COPYING' for use and warranty information
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

define(['dojo/_base/declare',
        'dojo/_base/lang',
        'dojo/dom-construct',
        'dojo/dom-style',
        'dojo/query',
        'dojo/on',
        'dojo/Evented',
        'dojo/Stateful',
        '../ipa',
        '../auth',
        '../reg',
        '../FieldBinder',
        '../FormMixin',
        '../text',
        '../util',
        './ContainerMixin'
       ],
       function(declare, lang,  construct, dom_style, query, on,
                Evented, Stateful, IPA, auth, reg, FieldBinder, FormMixin, text,
                util, ContainerMixin) {

    var ConfirmMixin = declare(null, IPA.confirm_mixin().mixin);

    /**
     * Base widget for PatternFly Login Page
     *
     * @class widgets.LoginScreenBase
     */
    var Terminal = function(spec) {

        var that = IPA.input_widget(spec);

        that.create = function(container) {

            that.widget_create(container);
            that.dom_node = construct.create('div', {
                id: this.id,
                'class': this['class']
            });

            if (that.container[0]) {
                construct.place(that.dom_node, that.container[0]);
            }

            this.render_content();

            return this.dom_node;
        };

        that.render_content =function() {

            var term_body = construct.create('div', {
                'class': ''
            }, this.dom_node);

            construct.empty(term_body);

            var terminal = construct.create('iframe', {
                'class': 'terminal',
                width: 705,
                height: 400
            }, term_body);
            that.terminal = terminal;
        };

        that.update = function() {
            var pkey = this.facet.get_pkey();
            if (!pkey) {
                dom_style.set(that.terminal, 'display', 'none');
            } else {
                dom_style.set(that.terminal, 'display', '');
            }
            that.terminal.setAttribute("src", "https://" + pkey + ":9090/cockpit/server/terminal.html");
        };

        return that;
    };
    return Terminal;
});