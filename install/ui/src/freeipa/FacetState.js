define(['dojo/_base/declare',
        'dojo/_base/lang',
        'dojo/Evented',
        'dojo/Stateful'
       ],
       function(declare, lang, Evented, Stateful) {
    /**
     * Facet state
     * @extends Stateful
     * @mixins Evented
     * @class facet.FacetState
     */
    var FacetState = declare([Stateful, Evented], {

        /**
         * Properties to ignore in clear and clone operation
         */
        _ignore_properties: {_watchCallbacks:1, onset:1,_updating:1, _inherited:1},

        /**
         * Gets object containing shallow copy of state's properties.
         */
        clone: function() {
            var clone = {};
            for(var x in this){
                if (this.hasOwnProperty(x) && !(x in this._ignore_properties)) {
                    clone[x] = lang.clone(this[x]);
                }
            }
            return clone;
        },

        /**
         * Unset all properties.
         */
        clear: function() {
            var undefined;
            for(var x in this){
                if (this.hasOwnProperty(x) && !(x in this._ignore_properties)) {
                    this.set(x, undefined);
                }
            }
            return this;
        },

        /**
         * Set a property
         *
         * Sets named properties on a stateful object and notifies any watchers of
         * the property. A programmatic setter may be defined in subclasses.
         *
         * Can be called with hash of name/value pairs.
         *
         * @fires set
         */
        set: function(name, value) {

            var old_state;
            var updating = this._updating;
            if (!updating) old_state = this.clone();
            this._updating = true;
            this.inherited(arguments);
            if (!updating) {
                delete this._updating;
                var new_state = this.clone();
                this.emit('set', old_state, new_state);
            }

            return this;
        },

        /**
         * Set completely new state. Old state is cleared.
         *
         * @fires reset
         */
        reset: function(object) {
            var old_state = this.clone();
            this._updating = true;
            this.clear();
            this.set(object);
            delete this._updating;
            var new_state = this.clone();
            this.emit('set', old_state, new_state);
            return this;
        }
    });

    return FacetState;
});
