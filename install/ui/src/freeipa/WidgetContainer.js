/*  Authors:
 *    Pavel Vomacka <pvomacka@redhat.com>
 *
 * Copyright (C) 2017 Red Hat
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
        'dojo/on',
        './builder',
        './ordered-map',
        './widget'
       ],
       function(declare, lang, Evented, on, builder, ordered_map, widget_mod) {

    /**
     * Container Mixin
     *
     * Manages child widgets.
     *
     * @class widgets.ContainerMixin
     */
    var WidgetContainer = declare([Evented], {

        /**
         * Parent container
         *
         * - usually facet or dialog
         */
        container: null,

        /**
         * FIXME add comment
         */
        new_container_for_child: null,

        /**
         * Childs
         * @property {ordered_map}
         */
        _widgets: null, //make it private

        /**
         * Builds widgets on add if not already built
         *
         * @property {widget.widget_builder}
         */
        widget_builder: null,

        /**
         * Raised after `create`
         * @event create
         */

        /**
         * Raised after 'clear_widgets`
         * @event clear
         */

        /**
         * Raised before `clear_widgets`
         *
         * - `clear_widgets` can be aborted by setting `event.abort=true`
         *
         * @event pre-clear
         */

        /**
         * Get widget by path
         * @param {string} path
         */
        get_widget: function(path) {

            var path_len = path.length;
            var i = path.indexOf('.');
            var name, child_path, widget, child;

            if (i >= 0) {
                name = path.substring(0, i);
                child_path = path.substring(i + 1);

                child = this._widgets.get(name);
                widget = child.widgets.get_widget(child_path);
            } else {
                widget = this._widgets.get(path);
            }

            return widget;
        },

        /**
         * Get all widgets
         * @return {Array.<IPA.widget>}
         */
        get_widgets: function() {
            return this._widgets.values;
        },

        /**
         * FIXME
         */
        get_widget_builder: function() {
            return this.widget_builder;
        },

        /**
         * Add widget
         * @param {IPA.widget|Object|String} widget
         *                           Field or widget spec
         */
        add_widget: function(widget) {
            widget.container = this;
            var built = this.widget_builder.build_widget(widget);

            this.register_widget_listeners(widget);
            this.emit('widget-add', { source: this, widget: widget });
            this._widgets.put(widget.name, built);
            return built;
        },

        /**
         * Add multiple widgets
         * @param {Array} widgets
         */
        add_widgets: function(widgets) {

            if (!widgets) return [];

            var built = [];
            for (var i=0; i<widgets.length; i++) {
                var w = this.add_widget(widgets[i]);
                built.push(w);
            }
            return built;
        },

        /**
         * Registers listeners for widget events
         * @param {IPA.widget} widget
         * @protected
         */
        register_widget_listeners: function(widget) {
            this.emit('register-widget', { source: this.container, widget: widget });
        },

        /**
         * Clear all widgets
         * @fires reset
         */
        clear_widgets: function() {

            var event = { source: this };
            this.emit('pre_clear', event);
            if (event.abort) return;

            var widgets = this.get_widgets();
            for (var i=0; i<widgets.length; i++) {
                var widget = widgets[i];
                widget.clear();
            }

            this.emit('clear', { source: this });
        },

        create: function(container) {

            var widgets = this.get_widgets();
            for (var i=0; i<widgets.length; i++) {
                var widget = widgets[i];

                var child_container = container;
                if(this.new_container_for_child) {
                    child_container = $('<div/>', {
                        name: widget.name,
                        'class': widget['class']
                    }).appendTo(container);
                }
                widget.create(child_container);

                if(i < widgets.length - 1) {
                    this.create_widget_delimiter(container);
                }
            }
        },

        create_widget_delimiter: function(container) {
        },

        /** Constructor */
        constructor: function(spec, container) {

            this.container = container;
            this._widgets = $.ordered_map();
            this.new_container_for_child = spec.new_container_for_child !== undefined ?
            spec.new_container_for_child : true;
            var facet = spec.facet || container;
            var builder_spec = {
                widget_options: {
                    entity: spec.entity,
                    facet: facet
                }
            };

            builder_spec.$factory = spec.widget_builder || widget_mod.widget_builder;
            this.widget_builder = builder.build(null, builder_spec);
            this.widget_builder.widget_options = this.widget_builder.widget_options || {};
            this.widget_builder.widget_options.parent = this.container;

            this.widget_container_create = this.create;
            this.widget_container_clear = this.clear;
        }
    });

    return WidgetContainer;
});
