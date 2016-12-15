//
// Copyright (C) 2016  FreeIPA Contributors see COPYING for license
//

define(['dojo/_base/declare',
        '../ipa'],
        function(declare, IPA) {
/**
 * EntityMixin
 *
 * Extension of Facet which adds support for entity.
 *
 * @class facets.EntityMixin
 */


var EntityMixin = declare([], {

    /**
     * Entity this facet belongs to
     * @property {entity.entity}
     */
    entity: null,

    /**
     * Return THE pkey of this facet. Basically the last one of pkeys list.
     *
     * @return {string} pkey
     */
    get_pkey: function() {
        var pkeys = this.get_pkeys();
        if (pkeys.length) {
            return pkeys[pkeys.length-1];
        }
        return '';
    },

    /**
     * Gets copy of pkeys list.
     * It automatically adds empty pkeys ('') for each containing entity if not
     * specified.
     *
     * One can get merge current pkeys with supplied if `pkeys` param is
     * specified.
     *
     * @param {string[]} pkeys new pkeys to merge
     * @return {string[]} pkeys
     */
    get_pkeys: function(pkeys) {
        var new_keys = [];
        var cur_keys = this.state.get('pkeys') || []; // INFO: state is in Facet
            // class, therefore it should be everytime present
        var current_entity = this.entity;
        pkeys = pkeys || [];
        var arg_l = pkeys.length;
        var cur_l = cur_keys.length;
        var tot_c = 0;
        while (current_entity) {
            if (current_entity.defines_key) tot_c++;
            current_entity = current_entity.get_containing_entity();
        }

        if (tot_c < arg_l || tot_c < cur_l) throw {
            error: 'Invalid pkeys count. Supplied more than expected.'
        };

        var arg_off = tot_c - arg_l;
        var cur_off = cur_l - tot_c;

        for (var i=0; i<tot_c; i++) {
            // first try to use supplied
            if (tot_c - arg_l - i <= 0) new_keys[i] = pkeys[i-arg_off];
            // then current
            else if (tot_c - cur_l - i <= 0) new_keys[i] = cur_keys[i-cur_off];
            // then empty
            else new_keys[i] = '';
        }

        return new_keys;
    },

    /**
     * Get pkey prefix.
     *
     * Opposite method to `get_pkey` - get's all pkeys except the last one.
     * @return {Array.<string>}
     */
    get_pkey_prefix: function() {
        var pkeys = this.get_pkeys();
        if (pkeys.length > 0) pkeys.pop();

        return pkeys;
    },

    constructor: function(spec) {
        this.entity = IPA.get_entity(spec.entity);
    }

});

return EntityMixin;

});
