define(['dojo/_base/declare',
        'dojo/_base/lang',
        'dojo/on',
        './builder',
        './field'
       ],
       function(declare, lang, on, builder, field_mod) {
    /**
     * Facet state
     * @extends Stateful
     * @mixins Evented
     * @class FieldContainer
     */
    var FieldContainer = declare([], {

        /**
         * Parent container
         *
         * - usually facet or dialog
         */
        container: null,

        /**
         * Fields
         * @property {ordered_map}
         */
        _fields: null,

        /**
         * Builds fields on add if not already built
         *
         * @property {field.field_builder}
         */
        field_builder: null,

        /**
         * Get field by name
         * @param {string} name
         */
        get_field: function(name) {
            return this._fields.get(name);
        },

        /**
         * Get all fields
         * @return {Array.<IPA.field>}
         */
        get_fields: function() {
            return this._fields.values;
        },

        get_fields_builder: function() {
            return this.field_builder;
        },

        /**
         * Add field
         * @param {IPA.field|Object|String} field
         *                           Field or field spec
         */
        add_field: function(field) {
            field.container = this.container;
            var built = this.field_builder.build_field(field);
            this.register_field_listeners(built); // FIXME
            this._fields.put(field.name, built);
            return built;
        },

        /**
         * Add multiple fields
         * @param {Array} fields
         */
        add_fields: function(fields) {

            if (!fields) return [];

            var built = [];
            for (var i=0; i<fields.length; i++) {
                var f = this.add_field(fields[i]);
                built.push(f);
            }
            return built;
        },



        /**
         * Registers listeners for field events
         * @param {IPA.field} field
         * @protected
         */
        register_field_listeners: function(field) {

            on(field, 'dirty-change', this.field_dirty_changed.bind(this.container));
        },

        /**
         * Field's dirty-change handler
         * @param {Object} event
         * @protected
         * @fires dirty-change
         */
        field_dirty_changed: function(event) {

            var old = this.dirty;

            if (event && event.dirty) {
                this.dirty = true;
            } else {
                this.dirty = this.dirty; // FIXME
            }

            if (old !== this.dirty) {
                this.emit('dirty-change', { source: this, dirty: this.dirty });
                //this.dirty_changed.notify([this.dirty]);
            }
        },


        widgets_created: function() {
            var fields = this._fields.values;

            for (var i=0; i<fields.length; i++) {
                fields[i].widgets_created();
            }
        },

        /**
         * Perform check if any field is dirty
         *
         * @return {boolean}
         *                  - true: some field is dirty
         *                  - false: all field's aren't dirty
         */
        _is_dirty: function() {
            var fields = this.get_fields();
            for (var i=0; i<fields.length; i++) {
                if (fields[i].enabled && fields[i].dirty) {
                    return true;
                }
            }
            return false;
        },

        /**
         * Reset all fields
         * @fires reset
         */
        _reset: function() {

            var fields = this.get_fields();
            for (var i=0; i<fields.length; i++) {
                var field = fields[i];
                field.reset();
            }
        },

        /**
         * Validate all fields
         * @return {boolean} true when all fields are valid
         */
        _validate: function() {
            var valid = true;
            var fields = this.get_fields();
            for (var i=0; i<fields.length; i++) {
                var field = fields[i];
                valid = field.validate() && field.validate_required() && valid;
            }
            return valid;
        },

        /**
         * Constructor
         */
        constructor: function(spec, container) {
            console.log("Constructor of FieldContainer")
            this._fields = $.ordered_map();
            this.container = container;
            var builder_spec = spec.field_builder || field_mod.field_builder;
            this.field_builder = builder.build(null, builder_spec);
            this.dirty = false;
            console.log('Constructor of FieldContainer - END')

            this.container_add_field = this.add_field; // FIXME Is it really needed?
        }
    });

    return FieldContainer;
});
