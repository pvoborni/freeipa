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
        'dojo/Evented',
        'dojo/dom-construct',
        'dojo/dom-class',
        'dojo/on',
        '../builder',
        '../FacetState',
        '../ipa', // for util functions
        '../jquery',
        '../text',
        '../widgets/ContainerMixin'
       ],
       function(declare, lang, Evented, construct, dom_class,
                on, builder, FacetState, IPA, $, text, ContainerMixin) {

    /**
     * Base class of Facet
     *
     * A future replacement/base class for `facet.facet`
     *
     * @class facets.Facet
     * @mixins widgets.ContainerMixin
     */
    var Facet = declare([Evented, ContainerMixin], {

        /**
         * Name of preferred facet container
         *
         * Leave unset to use default container.
         * @property {string}
         */
        preferred_container: null,

        /**
         * Facet name
         * @property {string}
         */
        name: null,

        /**
         * Facet label
         * @property {string}
         */
        label: null,

        /**
         * Facet title
         * @property {string}
         */
        title: null,

        /**
         * Facet tab label
         * @property {string}
         */
        tab_label: null,

        /**
         * Facet element's CSS class
         * @property {string}
         */
        'class': null,

        /**
         * Class which tells that the facet should be visible
         * @property {string}
         */
        active_class: 'active',

        /**
         * Data which are result of RPC commad.
         *
         * @property {Object} data
         */
        data: null,

        /**
         * dom_node of container
         * Suppose to contain dom_node of this and other facets.
         * @property {jQuery}
         */
        container_node: null,

        /**
         * dom_node which contains all content of this Facet.
         * @property {HTMLElement}
         * @readonly
         */
        dom_node: null,

        /**
         * DOM node which serves as container for child widgets
         * @property {HTMLElement}
         */
        children_node: null,

        /**
         * Redirection target information.
         *
         * Can be facet and/or entity name.
         * @property {Object}
         * @param {string} entity entity name
         * @param {string} facet facet name
         */
        redirect_info: null,

        /**
         * Facet requires authenticated user
         * @type {Boolean}
         */
        requires_auth: true,

        /**
         * Public state
         * @property {facet.FacetState}
         * @protected
         */
        state: null,

        /**
         * Raised when facet gets updated
         * @event
         */
        on_update: null,

        /**
         * Hard override for `needs_update()` logic. When set, `needs_update`
         * should always return this value.
         * @property {boolean}
         */
        _needs_update: null,

        /**
         * Timeout[s] from `last_modified` after which facet should be expired
         * @property {number} expire_timeout=600
         */
        expire_timeout: null,

        /**
         * Last time when facet was updated.
         * @property {Date}
         */
        last_updated: null,

        /**
         * Marks facet as expired - needs update
         *
         * Difference between `_needs_update` is that `expired_flag` should be
         * cleared after update.
         *
         * @property {boolean}
         */
        expired_flag: null,

        /**
         * Place where data from RPC command will be stored.
         *
         * @property {Object}
         */
        data: null,

        /**
         * Policies
         * @property {IPA.facet_policies}
         */
        policies: null,

        /**
         * Raised after `load()`
         * @event
         */
        post_load: null,

        /**
         * Name of containing facet of containing entity
         *
         * A guide for breadcrumb navigation
         *
         * @property {string}
         */
        containing_facet: null,

        redirect_error_codes: [4001],

        /**
         * Check if facet needs update
         *
         * That means if:
         *
         * - new state (`state` or supplied state) is different that old_state
         *   (`old_state`)
         * - facet is expired
         *   - `expired_flag` is set or
         *   - expire_timeout takes effect
         * - error is displayed
         *
         *
         * @param {Object} [new_state] supplied state
         * @return {boolean} needs update
         */
        needs_update: function(new_state) {

            if (this._needs_update !== undefined) return this._needs_update;

            new_state = new_state || this.state.clone();
            var needs_update = false;

            if (this.expire_timeout && this.expire_timeout > 0) {

                if (!this.last_updated) {
                    needs_update = true;
                } else {
                    var now = Date.now();
                    needs_update = (now - this.last_updated) > this.expire_timeout * 1000;
                }
            }

            needs_update = needs_update || this.expired_flag;
            needs_update = needs_update || this.error_displayed();

            needs_update = needs_update || this.state_diff(this.old_state || {}, new_state);

            return needs_update;
        },

        get_full_name: function() {
            return this.name;
        },

        load: function(data) {
            this.data = data;

            // check whether the facet have header. TODO: chech whether we can have
            // facet without header
            if (this.header) {
                this.header.load(data);
            }
        },

        /**
         * Checks if two objects has the same properties with equal values.
         *
         * @param {Object} a
         * @param {Object} b
         * @return {boolean} `a` and `b` are value-equal
         * @protected
         */
        state_diff: function(a, b) {
            var diff = false;
            var checked = {};

            var check_diff = function(a, b, skip) {

                var same = true;
                skip = skip || {};

                for (var key in a) {
                    if (a.hasOwnProperty(key) && !(key in skip)) {
                        var va = a[key];
                        var vb = b[key];
                        if (lang.isArray(va)) {
                            if (IPA.array_diff(va,vb)) {
                                same = false;
                                skip[a] = true;
                                break;
                            }
                        } else {
                            if (va != vb) {
                                same = false;
                                skip[a] = true;
                                break;
                            }
                        }
                    }
                }
                return !same;
            };

            diff = check_diff(a,b, checked);
            diff = diff || check_diff(b,a, checked);
            return diff;
        },

        /**
         * Sets expire flag
         */
        set_expired_flag: function() {
            this.expired_flag = true;
        },

        /**
         * Clears `expired_flag` and resets `last_updated`
         */
        clear_expired_flag: function() {
            this.expired_flag = false;
            this.last_updated = Date.now();
        },

        /**
         * Reset facet state to supplied
         *
         * @param {Object} state state to set
         */
        reset_state: function(state) {
            this.state.reset(state);
        },

        /**
         * Get copy of current state
         *
         * @return {Object} state
         */
        get_state: function() {
            return this.state.clone();
        },

        /**
         * Merges state into current and notifies it.
         *
         * @param {Object} state object to merge into current state
         */
        set_state: function(state) {
            this.state.set(state);
        },

        /**
         * Handle state set
         * @param {Object} old_state
         * @param {Object} state
         * @protected
         */
        on_state_set: function(old_state, state) {
            this.on_state_change(state);
        },

        /**
         * Handle state change
         * @param {Object} state
         * @protected
         */
        on_state_change: function(state) {

            this._notify_state_change(state);
        },

        /**
         * Fires `facet-state-change` event with given state as event parameter.
         *
         * @fires facet-state-change
         * @protected
         * @param {Object} state
         */
        _notify_state_change:  function(state) {
            this.emit('facet-state-change', {
                facet: this,
                state: state
            });
        },

        /**
         * Check if error is displayed (instead of content)
         *
         * @return {boolean} error visible
         */
        error_displayed: function() {
            return this.error_container &&
                        this.error_container.css('display') === 'block';
        }, //FIXME: Error container does not exists. - YES IN FACETS LIKE LOGIN

        /**
         * Create facet's HTML representation
         * NOTE: may be renamed to render
         */
        create: function() {

            if (this.dom_node) {
                construct.empty(this.dom_node);
            } else {
                this.dom_node = construct.create('div', {
                    'class': 'facet',
                    name: this.name,
                    'data-name': this.name
                });
            }
            if (this['class']) {
                dom_class.add(this.dom_node, this['class']);
            }
            if (this.container_node) {
                construct.place(this.dom_node, this.container_node);
            }

            this.children_node = this.dom_node;
            return this.dom_node;
        },

        /**
         * Render child widgets
         */
        render_children: function() {
            var widgets = this.widgets.get_widgets();

            for (var i=0;i<widgets.length; i++) {
                var widget = widgets[i];
                var modern = typeof widget.render === 'function';

                if (modern) {
                    widget.container_node = this.children_node;
                    widget.render();
                } else {
                    var container = $('<div/>').appendTo(this.children_node);
                    widget.create(container);
                }
            }
        },

        /**
         * Start refresh
         *
         * - get up-to-date data
         * - load the data
         * @abstract
         */
        refresh: function() {
        },

        /**
         * Clear all widgets
         * @abstract
         */
        clear: function() {
        },

        /**
         * Show facet
         *
         * - mark itself as active facet
         */
        show: function() {

            if (!this.dom_node) {
                this.create();
                this.render_children();
            } else if (!this.dom_node.parentElement) {
                construct.place(this.dom_node, this.container_node);
            }

            var state = this.state.clone();
            var needs_update = this.needs_update(state);
            this.old_state = state;

            if (needs_update) {
                this.clear();
            }

            dom_class.add(this.dom_node, 'active-facet');

            this.show_content();
            // FIXME: should be used -- login facet does not have header
            if (this.header) this.header.select_tab();

            if (needs_update) {
                this.refresh();
            }

            this.emit('show', { source: this });
        },

        /**
         * Show content container and hide error container.
         *
         * Opposite to `show_error`.
         * @protected
         */
        show_content: function() {
            // FIXME: should be used -- content is not on load facet
            if(this.content) this.content.css('display', 'block');
            if(this.error_container) this.error_container.css('display', 'none');
        },

        /**
         * Un-mark itself as active facet
         */
        hide: function() {
            if (this.dom_node.parentElement) {
                this.container_node.removeChild(this.dom_node);
            }
            dom_class.remove(this.dom_node, 'active-facet');
            this.emit('hide', { source: this });
        },

        /**
         * Initializes facet
         *
         * Facet builder should run this method after instantiation.
         * @param {Object} spec
         */
        init: function(spec) {
            this.widgets.add_widgets(spec.widgets || []);
            // this.actions.init(this);
            // this.header.init();
            // on(this.state, 'set', this.on_state_set);
            //
            // var buttons_spec = {
            //     $factory: IPA.control_buttons_widget,
            //     name: 'control-buttons',
            //     css_class: 'control-buttons',
            //     buttons: spec.control_buttons
            // };
            //
            // this.control_buttons = IPA.build(buttons_spec);
            // this.control_buttons.init(this);
            //
            // this.action_dropdown = IPA.build({
            //     $ctor: ActionDropdownWidget,
            //     action_names: this.header_actions,
            //     name: 'facet_actions',
            //     'class': 'dropdown facet-actions',
            //     right_aligned: true,
            //     toggle_text: text.get('@i18n:actions.title') + ' ',
            //     toggle_class: 'btn btn-default',
            //     toggle_icon: 'fa fa-angle-down'
            // });
            // this.action_dropdown.init(this);
        },

        can_leave: function() {
            return true;
        },

        show_leave_dialog: function(callback) {
            window.console.warning('Unimplemented');
        },

        /**
         * Get facet based on `redirect_info` and {@link
         * entity.entity.redirect_facet}
         * @return {facet.facet} facet to be redirected to
         */
        get_redirect_facet: function() {

            if (!this.entity) return;

            var entity = this.entity;
            while (entity.containing_entity) {
                entity = entity.get_containing_entity();
            }
            var facet_name = this.entity.redirect_facet;
            var entity_name = entity.name;
            var facet;

            if (this.redirect_info) {
                entity_name = this.redirect_info.entity || entity_name;
                facet_name = this.redirect_info.facet || facet_name;
            }

            if (!facet) {
                entity = IPA.get_entity(entity_name);
                facet = entity.get_facet(facet_name);
            }

            return facet;
        },

        /**
         * Redirect to redirection target
         */
        redirect: function() {

            var facet = this.get_redirect_facet();
            if (!facet) return;
            navigation.show(facet);
        },

        /**
         * Redirect if error thrown is
         * @protected
         */
        redirect_error: function(error_thrown) {

            /*If the error is in talking to the server, don't attempt to redirect,
              as there is nothing any other facet can do either. */
            for (var i=0; i<this.redirect_error_codes.length; i++) {
                if (error_thrown.code === this.redirect_error_codes[i]) {
                    this.redirect();
                    return;
                }
            }
        },

        /** Constructor */
        constructor: function(spec) {

            this.preferred_container = spec.preferred_container;
            this.name = spec.name;
            this.label = text.get(spec.label);
            this.tab_label = text.get(spec.tab_label || spec.label);
            this.title = text.get(spec.title || spec.label);
            this['class'] = spec['class'];
            this.container_node = spec.container_node;
            this.dom_node = spec.dom_node;
            this.redirect_info = spec.redirect_info;
            if (spec.requires_auth !== undefined) {
                this.requires_auth = spec.requires_auth;
            }
            this.state = new FacetState();
            this.on_update = IPA.observer();
            this._needs_update = spec.needs_update;
            this.expire_timeout = spec.expire_timeout || 600; //[seconds]
            this.expired_flag = true;

            on(this.state, 'set', this.on_state_set.bind(this));
            this.policies = IPA.facet_policies({
                container: this,
                policies: spec.policies
            });
            this.post_load = IPA.observer();
            this.containing_facet = spec.containing_facet;

            // FIXME: not nice
            this.facet_show = this.show;
            this.facet_create = this.create;
            this.facet_load = this.load;
            this.facet_init = this.init;
        }
    });

    return Facet;
});
