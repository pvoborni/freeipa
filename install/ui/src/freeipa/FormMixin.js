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
        'dojo/on',
        './field',
        './FieldContainer',
        './ordered-map'
       ],
       function(declare, on, field_mod, FieldContainer, ordered_map) {

    /**
     * Form mixin
     *
     * Manages fields and related logic.
     *
     * Expects that this mixin will be mixed in a class which will implement
     * `Stateful`.
     *
     * @class FormMixin
     */
    var FormMixin = declare([], {

        /**
         * Some field is dirty
         * @property {boolean}
         */
        dirty: null,

        /**
         * FieldContainer
         * @property {Object FieldContainer}
         */
        fields: null,


        /**
         * Raised when `dirty` state changes
         * @event dirty-change
         */

        /**
         * Raised after fields reset
         * @event reset
         */

        /**
         * Perform check if any field is dirty
         *
         * @return {boolean}
         *                  - true: some field is dirty
         *                  - false: all field's aren't dirty
         */
        is_dirty: function() {
            return this.fields._is_dirty();
        },

        /**
         * Reset all fields
         * @fires reset
         */
        reset: function() {

            this.field._reset();

            this.emit('reset', { source: this });
        },

        /**
         * Validate all fields
         * @return {boolean} true when all fields are valid
         */
        validate: function() {
            return this.fields._validate();
        },

        /** Constructor */
        constructor: function(spec) {
            this.fields = new FieldContainer(spec, this);

            this.container_add_field = this.add_field;
        }
    });

    return FormMixin;
});
